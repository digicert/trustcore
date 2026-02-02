/*
 * cert_enroll.c
 *
 * Implementation of cert enrollment generation.
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/mjson.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/datetime.h"
#include "../common/vlong.h"
#include "../common/base64.h"
#include "../common/common_utils.h"
#include "../common/int64.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../asn1/oidutils.h"

#include "../crypto/hw_accel.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs7.h"
#include "../crypto/pkcs10.h"
#include "../crypto/cert_chain.h"
#include "../crypto/cert_store.h"
#include "../crypto/asn1cert.h"

#ifndef __DISABLE_DIGICERT_CERT_SUBJECT_KEY_IDENTIFIER__
#include "../crypto/sha1.h"
#endif
#include "../crypto/sha256.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_api.h"
#include "../tap/tap_smp.h"
#include "../tap/tap_utils.h"
#include "../smp/smp_tpm2/smp_tap_tpm2.h"
#endif

#include "../crypto_interface/crypto_interface_sha256.h"
#include "../cert_enroll/cert_enroll.h"

#include <stdio.h>
#include <string.h>

#define MAX_LINE_LENGTH (256)
#define MAX_CSR_NAME_ATTRS (50)
#define SUPPORTED_DIGEST_ALGO_COUNT_RSA (4)
#define SUPPORTED_DIGEST_ALGO_COUNT_ECDSA (3)
#define MOC_NUM_EXT_KEY_USG_FIELDS (6)
#define MAX_NUM_SUBJECTALTNAMES (10)
#define MAX_SAN_ENTRY_ELEMENTS (3)
#define MAX_REQ_ATTRS (4)
#define MAX_ASN1_OBJECTS (100)
#define MAX_ASN1_BMPSTRING (100)
#define MAX_ASN1_BITSTRING (100)

typedef struct _extKeyUsageInfo
{
    ubyte serverAuth;
    ubyte clientAuth;
    ubyte codeSign;
    ubyte emailProt;
    ubyte timeStamp;
    ubyte ocspSign;
} extKeyUsageInfo;

typedef struct _DigestAlgoMap
{
    sbyte* digestName;
    sbyte4 digestType;

} DigestAlgoMap;

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addCsrSANField(
    CertCsrCtx *pCsrCtx,
    DER_ITEMPTR *ppRoot,
    byteBoolean *pIsCritical,
    sbyte *pId,
    sbyte **ppValue);

/*-------------------------------------------------------------------------*/

/* creates path/subdir/alias.suffix */
extern MSTATUS CERT_ENROLL_getFullPath(sbyte *pPath, sbyte *pSubDir, sbyte *pAlias,
                                       sbyte *pSuffix, sbyte **ppFullPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pTemp = NULL;
    sbyte *pTemp2 = NULL;

    /* suffix can be null, rest can't be (for now) */
    if (NULL == pPath || NULL == pSubDir || NULL == pAlias || NULL == ppFullPath)
        goto exit;

    status = COMMON_UTILS_addPathComponent(pSubDir, pAlias, &pTemp);
    if (OK != status)
        goto exit;

    status = COMMON_UTILS_addPathComponent(pPath, pTemp, &pTemp2);
    if (OK != status)
        goto exit;

    if (NULL != pSuffix)
    {
        /* re-use */
        (void) DIGI_FREE((void **) &pTemp);

        status = COMMON_UTILS_addPathExtension(pTemp2, pSuffix, &pTemp);
        if (OK != status)
            goto exit;

        *ppFullPath = pTemp; pTemp = NULL;
    }
    else
    {
        *ppFullPath = pTemp2; pTemp2 = NULL;
    }

exit:

    if (NULL != pTemp)
    {
        (void) DIGI_FREE((void **) &pTemp);
    }

    if (NULL != pTemp2)
    {
        (void) DIGI_FREE((void **) &pTemp2);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_addKeyCertAttributes(
    CertKeyCtx *pKeyCtx,
    AsymmetricKey *pKey,
    CertSignData signFun,
    CertDecryptData decFun,
    CertEnrollAlg keyAlgorithm,
    ubyte4 secureModuleId,
    byteBoolean primary,
    ubyte *pPassword,
    ubyte4 passwordLen,
    CertKeyHandle *pHandles
)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKeyCtx)
        goto exit;

    /* only one callback should be defined */
    status = ERR_INVALID_INPUT;
    if (NULL != signFun && NULL != decFun)
        goto exit;

    status = OK;
    pKeyCtx->pKey = pKey;
    if (NULL != signFun)
    {
        pKeyCtx->cb.signFun = signFun;
    }
    else
    {
        pKeyCtx->cb.decFun = decFun;
    }
    pKeyCtx->keyAlgorithm = keyAlgorithm;
    pKeyCtx->secureModuleId = secureModuleId;
    pKeyCtx->primary = primary;
    pKeyCtx->pPassword = pPassword;
    pKeyCtx->passwordLen = passwordLen;

    if (NULL != pHandles)
    {
        pKeyCtx->handle.pKey = pHandles->pKey; /* shallow copies */
        pKeyCtx->handle.keyLen = pHandles->keyLen;
        pKeyCtx->handle.pNonce = pHandles->pNonce;
        pKeyCtx->handle.nonceLen = pHandles->nonceLen;
    }

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CERT_ENROLL_addTapKeyAttributes(
    CertTapKeyCtx *pTapKeyCtx,
    TAP_PROVIDER source,
    TAP_KEY_USAGE keyUsage,
    TAP_SIG_SCHEME sigScheme,
    TAP_ENC_SCHEME encScheme
)
{
    if (NULL == pTapKeyCtx)
        return ERR_NULL_POINTER;

    pTapKeyCtx->source = source;
    pTapKeyCtx->keyUsage = keyUsage;
    pTapKeyCtx->sigScheme = sigScheme;
    pTapKeyCtx->encScheme = encScheme;

    return OK;
}
#endif

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_cleanupKeyCtx(
    CertKeyCtx *pKeyCtx
)
{
    return DIGI_MEMSET((ubyte *) pKeyCtx, 0x00, sizeof(CertKeyCtx));
}

/*-------------------------------------------------------------------------*/

static MSTATUS
CERT_ENROLL_createNameAttr(ubyte *pOid, ubyte type, ubyte *pValue, ubyte4 valueLen, nameAttr **pPNameAttr)
{
    nameAttr *pNameAttr     = NULL;
    int      actualValueLen = 0;
    MSTATUS status = OK;
    byteBoolean isValid = FALSE;

    if (0 == type &&
         (commonName_OID == pOid ||
          serialNumber_OID == pOid) )
    {
        /* Validate printable string */
        status = ASN1_validateEncoding(
            PRINTABLESTRING, pValue, valueLen, &isValid);
        if (OK != status)
        {
            goto exit;
        }

        if (FALSE == isValid && commonName_OID == pOid)
        {
            /* Check if we can encode it as UTF-8 string */
            status = ASN1_validateEncoding(
                UTF8STRING, pValue, valueLen, &isValid);
            if (OK != status)
            {
                goto exit;
            }

            if (TRUE == isValid)
            {
                type = UTF8STRING;
            }
        }

        if (FALSE == isValid)
        {
            if (commonName_OID == pOid)
            {
                status = ERR_CERT_ENROLL_INVALID_COMMON_NAME;
            }
            else if (serialNumber_OID == pOid)
            {
                status = ERR_CERT_ENROLL_INVALID_SERIAL_NUMBER;
            }
            else
            {
                status = ERR_CERT_ENROLL_INVALID_NAME_ATTR;
            }
            goto exit;
        }
    }

    if (OK > (status = DIGI_MALLOC((void**)&pNameAttr, sizeof(nameAttr))))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET((ubyte*) pNameAttr, 0x00, sizeof(nameAttr))))
    {
        goto exit;
    }
    pNameAttr->oid = pOid;
    pNameAttr->type = type;

    if ('\n' == pValue[valueLen-1])
        actualValueLen = valueLen -1;
    else
        actualValueLen = valueLen;

    if (OK > (status = DIGI_MALLOC((void**)&pNameAttr->value, actualValueLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(pNameAttr->value, 0x00, actualValueLen+1)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pNameAttr->value, (void*)pValue, actualValueLen)))
    {
        goto exit;
    }
    pNameAttr->valueLen = actualValueLen;

    *pPNameAttr = pNameAttr;
exit:
    if (OK > status)
    {
        if (pNameAttr)
        {
            if (pNameAttr->value)
            {
                DIGI_FREE((void**)&pNameAttr->value);
                pNameAttr->value = NULL;
            }
            if (pNameAttr)
            {
                DIGI_FREE((void**)&pNameAttr);
                pNameAttr = NULL;
            }
        }
    }
    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS
newExtensionAlloc(certExtensions **ppExtensions)
{
    MSTATUS status;
    extensions *pTemp = NULL;

    if (NULL == *ppExtensions)
    {
        status = DIGI_CALLOC((void **) ppExtensions, sizeof(certExtensions), 1);
        if (OK != status)
            goto exit;
    }

    if ((*ppExtensions)->otherExtCount > 0)
    {
        int oldCount = (*ppExtensions)->otherExtCount;
        int newCount = oldCount + 1;
        pTemp = (*ppExtensions)->otherExts;
        if (OK > (status = DIGI_MALLOC((void **)&((*ppExtensions)->otherExts), (newCount)*sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)(*ppExtensions)->otherExts, 0x00, (newCount)*sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(((*ppExtensions)->otherExts), pTemp, oldCount * sizeof(extensions))))
        {
            goto exit;
        }
        (*ppExtensions)->otherExtCount = newCount;
    }
    else
    {
        if (OK > (status = DIGI_MALLOC((void **)&((*ppExtensions)->otherExts), sizeof(extensions))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMSET((ubyte*)(*ppExtensions)->otherExts, 0x00, sizeof(extensions))))
        {
            goto exit;
        }
        (*ppExtensions)->otherExtCount = 1;
    }

exit:
    if (pTemp != NULL)
        DIGI_FREE((void **)&pTemp);

    return status;
}

/*-------------------------------------------------------------------------*/

/* TODO move to ca_mgmt or something like that? */
MOC_EXTERN void CERT_ENROLL_freeExtensions(certExtensions *pExtensions)
{
    if (pExtensions->otherExtCount > 0)
    {
        ubyte4 i;
        for (i = 0; i < pExtensions->otherExtCount; i++)
        {
            extensions *pExt = &(pExtensions->otherExts[i]);
            if (pExt->valueLen > 0)
            {
                if (NULL != pExt->oid)
                {
                    if( (pExt->oid != subjectAltName_OID) &&
                       (pExt->oid != subjectKeyIdentifier_OID) &&
                       (pExt->oid != id_ce_extKeyUsage_OID) &&
                       (pExt->oid != subjectDirectory_OID) &&
                       (pExt->oid != certificatePolicies_OID) )
                    {
                        pExt->oid = pExt->oid - 1;
                        FREE(pExt->oid);
                    }
                }
                FREE(pExt->value);
            }
        }
        FREE(pExtensions->otherExts);
    }
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_keyAlgorithmToString(
    CertEnrollAlg keyAlgorithm,
    sbyte **ppAllocatedStr)
{
    MSTATUS status;
    sbyte *pStr = "UNKNOWN";
    sbyte *pAllocatedStr = NULL;
    switch (keyAlgorithm)
    {
        case rsa2048:
            pStr = "RSA+2048";
            break;
        case rsa3072:
            pStr = "RSA+3072";
            break;
        case rsa4096:
            pStr = "RSA+4096";
            break;
        case ecdsaP256:
            pStr = "ECDSA+P256";
            break;
        case ecdsaP384:
            pStr = "ECDSA+P384";
            break;
        case ecdsaP521:
            pStr = "ECDSA+P521";
            break;
        case eddsaEd25519:
            pStr = "EDDSA+Ed25519";
            break;
        case eddsaEd448:
            pStr = "EDDSA+Ed448";
            break;
        case mldsa44:
            pStr = "MLDSA+44";
            break;
        case mldsa65:
            pStr = "MLDSA+65";
            break;
        case mldsa87:
            pStr = "MLDSA+87";
            break;
    }

    status = DIGI_MALLOC_MEMCPY(
        (void **) &pAllocatedStr, DIGI_STRLEN(pStr) + 1, pStr, DIGI_STRLEN(pStr));
    if (OK != status)
    {
        goto exit;
    }
    pAllocatedStr[DIGI_STRLEN(pStr)] = '\0'; /* ensure null termination */
    *ppAllocatedStr = pAllocatedStr;

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS
setSubjAltNameExtension(
    CertCsrCtx *pCsrCtx,
    SubjectAltNameAttr *pAttrs,
    int numSans,
    extensions *pSubAltNameExt)
{
    MSTATUS          status     =  OK;
    DER_ITEMPTR      pRoot      =  NULL;
    ubyte           *pEncoded   =  NULL;
    ubyte4           encodedLen =  0;
    int              pos        =  0;
    ubyte           *pIps       = NULL;
    ubyte4           numIps     = 0;
    ubyte           *pIpPtr     = NULL;
    ubyte4           ipLen      = 0;
    sbyte           *pValue     = NULL;

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
        else if (SubjectAltName_otherName == pAttrs[pos].subjectAltNameType)
        {
            if (OK > (status = DER_AddItem(pRoot, (CONSTRUCTED|CONTEXT|(&(pAttrs[pos]))->subjectAltNameType),
                                        (&(pAttrs[pos]))->subjectAltNameValue.dataLen,
                                        (&(pAttrs[pos]))->subjectAltNameValue.data, NULL)))
            {
                goto exit;
            }
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

    if (NULL != pCsrCtx && NULL == pCsrCtx->pKey && certEnrollAlgUndefined != pCsrCtx->keyAlgorithm)
    {
        status = CERT_ENROLL_keyAlgorithmToString(pCsrCtx->keyAlgorithm, &pValue);
        if (OK != status)
            goto exit;

        status = CERT_ENROLL_addCsrSANField(
            pCsrCtx, &pRoot, NULL, "san.directory_name.key_algorithm", &pValue);
        if (OK != status)
            goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if (NULL != pCsrCtx && (EXT_ENROLL_FLOW_TPM2_IAK == pCsrCtx->extFlow || EXT_ENROLL_FLOW_TPM2_IDEVID == pCsrCtx->extFlow))
    {
        status = CERT_ENROLL_addCsrSANField(
            pCsrCtx, &pRoot, NULL, "san.other_name.permanent_identifier", &pValue);
        if (OK != status)
            goto exit;

        status = CERT_ENROLL_addCsrSANField(
            pCsrCtx, &pRoot, NULL, "san.other_name.hardware_module_name", &pValue);
        if (OK != status)
            goto exit;
    }
#endif

    if (OK > (status = DER_Serialize(pRoot, &pEncoded, &encodedLen)))
    {
        goto exit;
    }
    pSubAltNameExt->oid = (ubyte*)subjectAltName_OID;
    pSubAltNameExt->isCritical = FALSE;
    pSubAltNameExt->value = pEncoded;
    pSubAltNameExt->valueLen = encodedLen;

exit:

    DIGI_FREE((void **) &pValue);

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

/*-------------------------------------------------------------------------*/

static MSTATUS
setExtKeyUsageExtension(certExtensions **ppExtensions, extKeyUsageInfo *pInfo)
{
    MSTATUS status;
    ubyte *pDer = NULL;
    ubyte4 derLen = 0;
    DER_ITEMPTR pSeq = NULL;
    ubyte4 i = 0;
    ubyte *pIter = NULL;
    ubyte *ppExtKeyUsageOids[] = {
        (ubyte *)id_kp_serverAuth_OID,
        (ubyte *)id_kp_clientAuth_OID,
        (ubyte *)id_kp_codeSigning_OID,
        (ubyte *)id_kp_emailProtection_OID,
        (ubyte *)id_kp_timeStamping_OID,
        (ubyte *)id_kp_OCSPSigning_OID
    };
    extensions *pExtKeyUsage;

    status = newExtensionAlloc(ppExtensions);
    if (OK != status)
        goto exit;

    status = DER_AddSequence(NULL, &pSeq);
    if (OK != status)
        goto exit;

    /* Traverse the structure one byte at at a time. The structure contains
     * only single byte fields so even with struct packing this logic should
     * be fine. If the structure is ever changed to include a member larger
     * than a byte, this will need to be revisited. */
    pIter = (ubyte *)pInfo;
    for (i = 0; i < MOC_NUM_EXT_KEY_USG_FIELDS; i++)
    {
        if (TRUE == *pIter)
        {
            status = DER_AddOID(pSeq, ppExtKeyUsageOids[i], 0);
            if (OK != status)
                goto exit;
        }

        pIter++;
    }

    status = DER_Serialize(pSeq, &pDer, &derLen);
    if (OK != status)
        goto exit;

    pExtKeyUsage = &((*ppExtensions)->otherExts[(*ppExtensions)->otherExtCount-1]);
    pExtKeyUsage->oid = (ubyte *)id_ce_extKeyUsage_OID;
    pExtKeyUsage->isCritical = FALSE;
    pExtKeyUsage->value = pDer;
    pExtKeyUsage->valueLen = derLen;

exit:

    if (pSeq)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSeq);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CERT_SUBJECT_KEY_IDENTIFIER__
static MSTATUS
setSubjectKeyIdentifierExtension(certExtensions **ppExtensions, ubyte *pValue, ubyte4 valueLen)
{
    MSTATUS status;
    ubyte *pDer = NULL;

    extensions *pSubjectKeyId;

    status = newExtensionAlloc(ppExtensions);
    if (OK != status)
        goto exit;

    /* Create an octet string directly, leave space for tag and length */
    status = DIGI_MALLOC((void **) &pDer, valueLen + 2);
    if (OK != status)
        goto exit;

    pDer[0] = OCTETSTRING;
    pDer[1] = (ubyte) valueLen;

    status = DIGI_MEMCPY(pDer + 2, pValue, valueLen);
    if (OK != status)
        goto exit;

    pSubjectKeyId = &((*ppExtensions)->otherExts[(*ppExtensions)->otherExtCount-1]);
    pSubjectKeyId->oid = (ubyte *)subjectKeyIdentifier_OID;
    pSubjectKeyId->isCritical = FALSE;
    pSubjectKeyId->value = pDer; pDer = NULL;
    pSubjectKeyId->valueLen = valueLen + 2;

exit:

    if (NULL != pDer)
    {
        (void) DIGI_FREE((void **) &pDer);
    }

    return status;
}
#endif

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_setCertDates(certDistinguishedName *pDest, TimeDate *pStart, TimeDate *pEnd)
{
    MSTATUS status = OK;

    if (NULL == pDest)
        return ERR_NULL_POINTER;

    if (NULL != pStart)
    {
        (void) DIGI_FREE((void **) &pDest->pStartDate);
        status = DIGI_CALLOC((void **) &pDest->pStartDate, 1, 16);
        if (OK != status)
            goto exit;

        (void) DATETIME_convertToValidityString(pStart, pDest->pStartDate); /* always returns OK */
    }

    if (NULL != pEnd)
    {
        (void) DIGI_FREE((void **) &pDest->pEndDate);
        status = DIGI_CALLOC((void **) &pDest->pEndDate, 1, 16);
        if (OK != status)
            goto exit;

        (void) DATETIME_convertToValidityString(pEnd, pDest->pEndDate);
    }

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS
CERT_ENROLL_createCertDistinguishedName(nameAttr **pPnameAttr, int nameAttrLen, certDistinguishedName **ppDest)
{
    MSTATUS    status         = OK;
    ubyte4     rdnOffset      = 0;
    relativeDN *pRDN          = NULL;
    nameAttr   *pNameAttr     = NULL;
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
        goto exit;

    if (OK > (status = DIGI_MALLOC((void**)&(pDest->pDistinguishedName), nameAttrLen*sizeof(relativeDN))))
    {
        goto exit;
    }
    pDest->dnCount = nameAttrLen;

    rdnOffset = 0;
    for (pRDN = pDest->pDistinguishedName+rdnOffset; rdnOffset < pDest->dnCount; pRDN = pDest->pDistinguishedName+rdnOffset)
    {
        /* Outer  loop to loop through the attributes from configuration file */
        pNameAttr = pPnameAttr[rdnOffset];
        pRDN->pNameAttr = pNameAttr;
        pRDN->nameAttrCount = 1;
        rdnOffset = rdnOffset + 1;
    }

    *ppDest = pDest; pDest = NULL;

exit:

    if (pDest != NULL)
    {
        (void) CA_MGMT_freeCertDistinguishedName(&pDest);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_eval(
    CertCsrCtx *pCsrCtx,
    sbyte *pExpr,
    ubyte4 exprLen,
    sbyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status;
    byteBoolean goBackToDefault = FALSE;
    ubyte *pValue = NULL;
    ubyte4 valueLen = 0;

    DIGI_FREE((void **) ppVal);
    *pValLen = 0;

    if (NULL == pCsrCtx || NULL == pCsrCtx->evalFunction)
    {
        /* No eval function, use value as is */
        status = DIGI_MALLOC_MEMCPY(
            (void **) ppVal, exprLen + 1, pExpr, exprLen);
        if (OK != status)
        {
            goto exit;
        }

        (*ppVal)[exprLen] = '\0'; /* ensure null termination */
        *pValLen = exprLen;
    }
    else
    {
        status = pCsrCtx->evalFunction(
            pCsrCtx->pEvalFunctionArg, &goBackToDefault,
            (ubyte *) pExpr, exprLen, NULL, &valueLen);
        if (goBackToDefault)
        {
            status = ERR_CERT_ENROLL_NO_DEFAULT;
            goto exit;
        }
        else if (ERR_BUFFER_TOO_SMALL != status || !valueLen)
        {
            /* Default length */
            valueLen = MAX_LINE_LENGTH;
        }

        status = DIGI_MALLOC((void **) &pValue, valueLen + 1);
        if (OK != status)
        {
            goto exit;
        }

        status = pCsrCtx->evalFunction(
            pCsrCtx->pEvalFunctionArg, &goBackToDefault,
            (ubyte *) pExpr, exprLen, pValue, &valueLen);
        if (goBackToDefault)
        {
            status = ERR_CERT_ENROLL_NO_DEFAULT;
            goto exit;
        }
        else if (OK != status)
        {
            goto exit;
        }

        pValue[valueLen] = '\0'; /* ensure null termination */

        *ppVal = (sbyte *) pValue; pValue = NULL;
        *pValLen = valueLen;
    }

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_addCsrAttributeTOML(
    ubyte *pIn,
    ubyte4 inLen,
    CertCsrCtx *pCsrCtx,
    certDistinguishedName **ppSubject,
    certExtensions **ppExtensions)
{
    MSTATUS               status                            = OK;
    char                  *pToken                           = NULL;
    char                  *value                            = NULL;
    int                   nameAttrCount                     = 0;
    char                  *search                           = "=";
    ubyte4                len                               = 0;
    nameAttr              *pNameAttr[MAX_CSR_NAME_ATTRS]    = {0};
    char                  line[MAX_LINE_LENGTH + 1];
    ubyte *pStartPtr = pIn;
    ubyte *pEndPtr = NULL;
    ubyte *pLastPtr = pIn + inLen;
    byteBoolean sanSet = FALSE;
    sbyte *pEvaluatedValue = NULL;
    ubyte4 evaluatedValueLen = 0;

    if (NULL == ppExtensions)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    while((uintptr) pStartPtr < (uintptr) pLastPtr)
    {
        pEndPtr = memchr(pStartPtr, (int) '\n', (ubyte4) (pLastPtr - pStartPtr));
        if (NULL == pEndPtr)
        {
            /* No newline found, this is the last line */
            pEndPtr = pLastPtr;
        }

        if (pEndPtr == pStartPtr)
        {
            /* empty line, skip */
            pStartPtr = pEndPtr + 1;
            continue;
        }
        (void) DIGI_MEMCPY(line, pStartPtr, (ubyte4) (pEndPtr - pStartPtr));
        line[(ubyte4)(pEndPtr - pStartPtr)] = '\0';

        /* get ready for next iteration */
        pStartPtr = pEndPtr + 1;

        /* now parse line */

        /* Discard commented line */
        if (*line == '#')
            continue;
        pToken = strtok(line, search);
        if (pToken == NULL)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        if (0 == DIGI_STRCMP((const sbyte *)"commonName", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            CERT_ENROLL_createNameAttr((ubyte *)commonName_OID, 0, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
            nameAttrCount++;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"serialNumber", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            CERT_ENROLL_createNameAttr((ubyte *)serialNumber_OID, 0, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
            nameAttrCount++;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"countryName", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            CERT_ENROLL_createNameAttr((ubyte *)countryName_OID, 0, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
            nameAttrCount++;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"localityName", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            CERT_ENROLL_createNameAttr((ubyte *)localityName_OID, 0, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
            nameAttrCount++;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"stateOrProvinceName", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            CERT_ENROLL_createNameAttr((ubyte *)stateOrProvinceName_OID, 0, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
            nameAttrCount++;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"organizationName", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            CERT_ENROLL_createNameAttr((ubyte *)organizationName_OID, 0, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
            nameAttrCount++;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"organizationalUnitName", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            CERT_ENROLL_createNameAttr((ubyte *)organizationalUnitName_OID, 0, (ubyte *)value, len, &pNameAttr[nameAttrCount]);
            nameAttrCount++;
        } /* hasBasicContraints (ie spelled wrong) is here for legacy purposes */
        else if (0 == DIGI_STRCMP((const sbyte *)"hasBasicConstraints", (const sbyte *)pToken) || 0 == DIGI_STRCMP((const sbyte *)"hasBasicContraints", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);
            if ('\n' == value[len-1])
                len = len -1;

            if (NULL == *ppExtensions)
            {
                status = DIGI_CALLOC((void **) ppExtensions, sizeof(certExtensions), 1);
                if (OK != status)
                    goto exit;
            }

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            if ((0 == DIGI_STRNICMP((const sbyte *)"true", (const sbyte *)value, len)))
            {
                (*ppExtensions)->hasBasicConstraints = 1;
            }
            else
            {
                (*ppExtensions)->hasBasicConstraints = 0;
            }
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"isCA", (const sbyte *)pToken))
        {
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);
            if ('\n' == value[len-1])
                len = len -1;

            if (NULL == *ppExtensions)
            {
                status = DIGI_CALLOC((void **) ppExtensions, sizeof(certExtensions), 1);
                if (OK != status)
                    goto exit;
            }

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            if ((0 == DIGI_STRNICMP((const sbyte *)"true", (const sbyte *)value, len)))
            {
                (*ppExtensions)->isCA = TRUE;
            }
            else
            {
                (*ppExtensions)->isCA = FALSE;
            }

        }
        else if (0 == DIGI_STRCMP((const sbyte *)"certPathLen", (const sbyte *)pToken))
        {
            char *actualValue = NULL;
            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);
            if ('\n' == value[len-1])
                len = len -1;

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            actualValue = MALLOC(len + 1);
            if (NULL == actualValue)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(actualValue, value, len);
            *(actualValue+len) = '\0';

            if (NULL == *ppExtensions)
            {
                status = DIGI_CALLOC((void **) ppExtensions, sizeof(certExtensions), 1);
                if (OK != status)
                {
                    FREE(actualValue);
                    goto exit;
                }
            }

            (*ppExtensions)->certPathLen = (sbyte)atoi(actualValue);
            FREE(actualValue);
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"keyUsage", (const sbyte *)pToken))
        {
            char   ch  = '\0';
            ubyte2 res = 0;
            char   keyUsageVal[MAX_LINE_LENGTH];
            int    i = 0, k = 0;

            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
            while(((ubyte4)i) <= len)
            {
                ch = value[i];
                if (ch == ',' || ch == '\n' || ch == '\0')
                {
                    if (0 == DIGI_STRCMP((const sbyte *)"digitalSignature", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << digitalSignature);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"nonRepudiation", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << nonRepudiation);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"keyEncipherment", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << keyEncipherment);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"dataEncipherment", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << dataEncipherment);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"keyAgreement", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << keyAgreement);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"keyCertSign", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << keyCertSign);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"cRLSign", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << cRLSign);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"encipherOnly", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << encipherOnly);
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"decipherOnly", (const sbyte *)keyUsageVal))
                    {
                        res = res + (1 << decipherOnly);
                    }
                    DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                    k  = 0;
                    i++;
                }
                else if (ch == ' ')
                {
                    i++;
                    continue;
                }
                else
                {
                    keyUsageVal[k++] = ch;
                    i++;
                }
            }

            if (NULL == *ppExtensions)
            {
                status = DIGI_CALLOC((void **) ppExtensions, sizeof(certExtensions), 1);
                if (OK != status)
                    goto exit;
            }

            (*ppExtensions)->hasKeyUsage = TRUE;
            (*ppExtensions)->keyUsage = res;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"subjectAltNames", (const sbyte *)pToken))
        {
            char   ch  = '\0';
            char   keyUsageVal[MAX_LINE_LENGTH];
            ubyte4    offset = 0, sansCount = 0, numsans = 0;
            ubyte4    i = 0, k = 0;
            char  *end;
            char  count[MAX_NUM_SUBJECTALTNAMES];/*This variable is used to store the count of subjectAltNames from cofiguration*/

            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            /*Caluclate num of SANS */
            DIGI_MEMSET((ubyte*)count, 0x00, MAX_NUM_SUBJECTALTNAMES);
            while((i <= len) && (value[i] != '\n') && (value[i] != ';') && (value[i] != '\0'))
            {
                if(i == MAX_NUM_SUBJECTALTNAMES)
                {
                    status = ERR_CERT_ENROLL_SAN_OVERFLOW;
                    goto exit;
                }
                count[i] = value[i];
                i++;
            }
            if (0 == (numsans = strtol(count, &end, 10)))
            {
                /* No SubjectAltNames present */
                continue;
            }
            if (value == end)
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }
            SubjectAltNameAttr *sans = MALLOC(numsans * sizeof(SubjectAltNameAttr));
            if (NULL == sans)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMSET((ubyte *)sans, 0x00, numsans * sizeof(SubjectAltNameAttr));
            DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
            i++;/*Move to next position */
            while(i <= len)
            {
                ch = value[i];
                if (ch == ',' || ch == ';' || ch == '\n' || ch == '\0')
                {
                    if (0 == offset)
                    {
                        /* SANS value */
                        ubyte4 dataLen = DIGI_STRLEN((sbyte*)keyUsageVal);
                        (&(sans[sansCount]))->subjectAltNameValue.data = MALLOC(dataLen + 1);
                        DIGI_MEMSET((ubyte*)(&(sans[sansCount]))->subjectAltNameValue.data, 0x00, dataLen + 1);
                        DIGI_MEMCPY((&(sans[sansCount]))->subjectAltNameValue.data, keyUsageVal, dataLen);
                        (&sans[sansCount])->subjectAltNameValue.dataLen = dataLen;
                        offset++;
                    }
                    else if (1 == offset)
                    {
                        /* Type of SANs */
                        int type = atoi(keyUsageVal);
                        (&(sans[sansCount]))->subjectAltNameType = (ubyte)type;
                        offset = 0;
                    }
                    if (ch == ';')
                        sansCount++;
                    DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                    k = 0;
                    i++;
                }
                else if (ch == ' ')
                {
                    i++;
                    continue;
                }
                else
                {
                    keyUsageVal[k++] = ch;
                    i++;
                }
            }

            status = newExtensionAlloc(ppExtensions);
            if (OK != status)
                goto free_sans;

            status = setSubjAltNameExtension(pCsrCtx, sans, numsans, &(*ppExtensions)->otherExts[(*ppExtensions)->otherExtCount - 1]);
free_sans:
            /* Free the SubjectAltNameAttr array */
            if (NULL != sans)
            {
                i = 0;
                for (; i < numsans; i++)
                {
                    SubjectAltNameAttr *sanattr = &sans[i];
                    if (sanattr->subjectAltNameValue.data != NULL)
                    {
                        FREE(sanattr->subjectAltNameValue.data);
                    }
                }
                FREE(sans);
                sans = NULL;
            }
            if (OK != status)
                goto exit;

            sanSet = TRUE;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)"extendedKeyUsage", (const sbyte *)pToken))
        {
            char   ch  = '\0';
            char   keyUsageVal[MAX_LINE_LENGTH];
            int    i = 0, k = 0;
            extKeyUsageInfo extKeyUsage = {0};

            value = strtok(NULL, search);
            if (value == NULL || *value == '\n')
                continue;
            len = DIGI_STRLEN((const sbyte *)value);

            status = CERT_ENROLL_eval(pCsrCtx, value, len, &pEvaluatedValue, &evaluatedValueLen);
            if (OK != status)
                goto exit;

            value = pEvaluatedValue;
            len = evaluatedValueLen;

            DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
            while(((ubyte4)i) <= len)
            {
                ch = value[i];
                if (ch == ',' || ch == '\n' || ch == '\0')
                {
                    if (0 == DIGI_STRCMP((const sbyte *)"serverAuth", (const sbyte *)keyUsageVal))
                    {
                        extKeyUsage.serverAuth = TRUE;
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"clientAuth", (const sbyte *)keyUsageVal))
                    {
                        extKeyUsage.clientAuth = TRUE;
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"codeSigning", (const sbyte *)keyUsageVal))
                    {
                        extKeyUsage.codeSign = TRUE;
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"emailProtection", (const sbyte *)keyUsageVal))
                    {
                        extKeyUsage.emailProt = TRUE;
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"timeStamping", (const sbyte *)keyUsageVal))
                    {
                        extKeyUsage.timeStamp = TRUE;
                    }
                    else if (0 == DIGI_STRCMP((const sbyte *)"OCSPSigning", (const sbyte *)keyUsageVal))
                    {
                        extKeyUsage.ocspSign = TRUE;
                    }
                    DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                    k  = 0;
                    i++;
                }
                else if (ch == ' ')
                {
                    i++;
                    continue;
                }
                else
                {
                    keyUsageVal[k++] = ch;
                    i++;
                }
            }

            status = setExtKeyUsageExtension(ppExtensions, &extKeyUsage);
            if (OK != status)
                goto exit;
        }
    }

    if (NULL != pCsrCtx && NULL == pCsrCtx->pKey && certEnrollAlgUndefined != pCsrCtx->keyAlgorithm && FALSE == sanSet)
    {
        status = newExtensionAlloc(ppExtensions);
        if (OK != status)
            goto exit;

        status = setSubjAltNameExtension(pCsrCtx, NULL, 0, &(*ppExtensions)->otherExts[(*ppExtensions)->otherExtCount - 1]);
        if (OK != status)
            goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != pCsrCtx && (EXT_ENROLL_FLOW_TPM2_IAK == pCsrCtx->extFlow || EXT_ENROLL_FLOW_TPM2_IDEVID == pCsrCtx->extFlow) && FALSE == sanSet)
    {
        status = newExtensionAlloc(ppExtensions);
        if (OK != status)
            goto exit;

        status = setSubjAltNameExtension(pCsrCtx, NULL, 0, &(*ppExtensions)->otherExts[(*ppExtensions)->otherExtCount - 1]);
        if (OK != status)
            goto exit;
    }
#endif

    /* Create CertDistinguishedName */
    status = CERT_ENROLL_createCertDistinguishedName(pNameAttr, nameAttrCount, ppSubject);

exit:

    DIGI_FREE((void **) &pEvaluatedValue);
    /* extensions will be freed by the calling method whether error or not */

    return status;
}

/*-------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CERT_SUBJECT_KEY_IDENTIFIER__
MOC_EXTERN MSTATUS CERT_ENROLL_addSubjectKeyIdentifier(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    certExtensions *pExtensions
)
{
    MSTATUS status;
    ubyte pValue[SHA1_RESULT_SIZE];

    status = ASN1CERT_sha1PublicKey(MOC_ASYM(hwAccelCtx) pKey, pValue);
    if (OK != status)
        goto exit;

    status = setSubjectKeyIdentifierExtension(&pExtensions, pValue, SHA1_RESULT_SIZE);

exit:

    return status;
}
#endif

/*-------------------------------------------------------------------------*/

#ifdef __ENABLE_CERT_ENROLL_ALT_FORMATS__
static TpecJsonStrings_t estCsrAttrib[] =
{
    {TP_CSR_ATTRIB_CN, TK_CSR_ATTRIB_CN, JSON_String, 0},
    {TP_CSR_ATTRIB_C, TK_CSR_ATTRIB_C, JSON_String, 1},
    {TP_CSR_ATTRIB_ST, TK_CSR_ATTRIB_ST, JSON_String, 1},
    {TP_CSR_ATTRIB_L, TK_CSR_ATTRIB_L, JSON_String, 1},
    {TP_CSR_ATTRIB_O, TK_CSR_ATTRIB_O, JSON_String, 1},
    {TP_CSR_ATTRIB_OU, TK_CSR_ATTRIB_OU, JSON_String, 1},
    {TP_CSR_ATTRIB_EMAIL, TK_CSR_ATTRIB_EMAIL, JSON_String, 1},
    {TP_CSR_ATTRIB_SALTNM, TK_CSR_ATTRIB_SALTNM, JSON_String, 1},
    {TP_CSR_ATTRIB_BCONS, TK_CSR_ATTRIB_BCONS, JSON_True, 1},
    {TP_CSR_ATTRIB_ISCA, TK_CSR_ATTRIB_ISCA, JSON_True, 1},
    {TP_CSR_ATTRIB_CERTPLEN, TK_CSR_ATTRIB_CERTPLEN, JSON_Integer, 1},
    {TP_CSR_ATTRIB_KEYUSG, TK_CSR_ATTRIB_KEYUSG, JSON_String, 1},
    {TP_CSR_ATTRIB_EXTKEYUSG, TK_CSR_ATTRIB_EXTKEYUSG, JSON_String, 1},
    {TP_CSR_ATTRIB_SERIALNUMBER, TK_CSR_ATTRIB_SERIALNUMBER, JSON_String, 1}
};

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addCsrAttributeJSONAlt(ubyte *pIn, ubyte4 inLen, certDistinguishedName **ppSubject, requestAttributesEx *pPkcs10Attribs)
{
    MSTATUS status = OK;
    nameAttr *pNameAttrib[MAX_CSR_NAME_ATTRS] = {0};
    JSON_ContextType *pJCtx = NULL;
    ubyte4 tokens = 0;
    ubyte4 index =0;
    JSON_TokenType token = {0};
    ubyte  i_num = 0;
    ubyte4 attrCnt = 0;

     /* Internal method, NULL checks not necc */
    status = JSON_acquireContext( &pJCtx);
    if( OK != status)
        goto exit;

    status = JSON_parse(pJCtx, (const sbyte *)pIn, inLen, &tokens);
    if( OK != status)
        goto exit;

    tokens = sizeof(estCsrAttrib)/sizeof(TpecJsonStrings_t);
    for(i_num = 0; i_num < tokens; i_num++)
    {
        status = JSON_getObjectIndex(pJCtx, (sbyte *) estCsrAttrib[i_num].tag,
                                                       0, &index, FALSE);
        if (OK == status)
        {
            status = JSON_getToken(pJCtx, index + 1, &token);
        }
        else
        {
            if(!estCsrAttrib[i_num].optional)
            {
                goto exit;
            }
            else
            {
                status = OK;
                continue;
            }
        }
        switch(estCsrAttrib[i_num].tag_key)
        {
            case TK_CSR_ATTRIB_CN:
            if ((OK == status) && (JSON_String == token.type))
            {
                status = CERT_ENROLL_createNameAttr((ubyte *)commonName_OID, 0, (ubyte *)token.pStart, token.len, &pNameAttrib[attrCnt]);
                attrCnt++;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_C:
            if ((OK == status) && (JSON_String == token.type))
            {
                status = CERT_ENROLL_createNameAttr((ubyte *)countryName_OID, 0, (ubyte *)token.pStart, token.len, &pNameAttrib[attrCnt]);
                attrCnt++;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_ST:
            if ((OK == status) && (JSON_String == token.type))
            {
                status = CERT_ENROLL_createNameAttr((ubyte *)stateOrProvinceName_OID, 0, (ubyte *)token.pStart, token.len, &pNameAttrib[attrCnt]);
                attrCnt++;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_L:
            if ((OK == status) && (JSON_String == token.type))
            {
                status = CERT_ENROLL_createNameAttr((ubyte *)localityName_OID, 0, (ubyte *)token.pStart, token.len, &pNameAttrib[attrCnt]);
                attrCnt++;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_O:
            if ((OK == status) && (JSON_String == token.type))
            {
                status = CERT_ENROLL_createNameAttr((ubyte *)organizationName_OID, 0, (ubyte *)token.pStart, token.len, &pNameAttrib[attrCnt]);
                attrCnt++;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_OU:
            if ((OK == status) && (JSON_String == token.type))
            {
                status = CERT_ENROLL_createNameAttr((ubyte *)organizationalUnitName_OID, 0, (ubyte *)token.pStart, token.len, &pNameAttrib[attrCnt]);
                attrCnt++;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_EMAIL:
            if ((OK == status) && (JSON_String == token.type))
            {
                status = CERT_ENROLL_createNameAttr((ubyte *)pkcs9_emailAddress_OID, 0, (ubyte *)token.pStart, token.len, &pNameAttrib[attrCnt]);
                attrCnt++;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_SALTNM:
            if ((OK == status) && (JSON_String == token.type))
            {
                char   ch  = '\0';
                char ppSANEntry[MAX_SAN_ENTRY_ELEMENTS][MAX_LINE_LENGTH] = { 0 };
                ubyte4    offset = 0, sansCount = 0, numsans = 0;
                ubyte4    i = 0, k = 0;
                char  *end;
                char  count[MAX_NUM_SUBJECTALTNAMES];/*This variable is used to store the count of subjectAltNames from cofiguration*/

                /*Caluclate num of SANS */
                DIGI_MEMSET((ubyte*)count, 0x00, MAX_NUM_SUBJECTALTNAMES);
                while((i <= token.len) && (token.pStart[i] != '\0') && (token.pStart[i] != ';'))
                {
                    if(i == MAX_NUM_SUBJECTALTNAMES)
                    {
                        break;
                    }
                    count[i] = token.pStart[i];
                    i++;
                }
                if (0 == (numsans = strtol(count, &end, 10)))
                {
                    /* No SubjectAltNames present */
                    continue;
                }
                if (token.pStart == (const sbyte *)end)
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
                SubjectAltNameAttr *sans = MALLOC(numsans * sizeof(SubjectAltNameAttr));
                if (NULL == sans)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMSET((ubyte *)sans, 0x00, numsans * sizeof(SubjectAltNameAttr));
                i++;/*Move to next position */
                while (i <= token.len)
                {
                    ch = token.pStart[i];

                    if (ch == ',' || ch == ';' || i == token.len)
                    {
                        if (ch == ';' || i == token.len)
                        {
                            /* End of the current SAN entry, process all elements */

                            /* Last value is SAN type */
                            int type = atoi(ppSANEntry[offset]);
                            (&(sans[sansCount]))->subjectAltNameType = (ubyte)type;

                            /* Based on the SAN type, process other elements */
                            if (SubjectAltName_otherName == type)
                            {
                                if (0 == offset)
                                {
                                    status = ERR_INVALID_ARG;
                                    goto exit;
                                }
                                else if ( (2 == offset) &&
                                          (0 != DIGI_STRLEN(ppSANEntry[1])) )
                                {
                                    /* No OtherName OIDs with a user provided
                                     * value are supported */
                                    status = ERR_NOT_IMPLEMENTED;
                                    goto exit;
                                }
                                else
                                {
                                    status = ERR_INVALID_ARG;
                                    goto exit;
                                }
                            }
                            else
                            {
                                if (offset != 1)
                                {
                                    status = ERR_INVALID_ARG;
                                    goto exit;
                                }

                                /* SAN value */
                                ubyte4 dataLen = DIGI_STRLEN((sbyte*) ppSANEntry[0]);
                                (&(sans[sansCount]))->subjectAltNameValue.data = MALLOC(dataLen + 1);
                                DIGI_MEMSET((ubyte*)(&(sans[sansCount]))->subjectAltNameValue.data, 0x00, dataLen + 1);
                                DIGI_MEMCPY((&(sans[sansCount]))->subjectAltNameValue.data, ppSANEntry[0], dataLen);
                                (&sans[sansCount])->subjectAltNameValue.dataLen = dataLen;
                            }

                            DIGI_MEMSET((ubyte *) ppSANEntry, 0x00, sizeof(ppSANEntry));
                            offset = 0;
                            sansCount++;
                        }
                        else if (ch == ',')
                        {
                            offset++;
                            if (offset >= MAX_SAN_ENTRY_ELEMENTS)
                            {
                                status = ERR_INDEX_OOB;
                                goto exit;
                            }
                        }
                        k = 0;
                        i++;
                    }
                    else if (ch == ' ')
                    {
                        i++;
                        continue;
                    }
                    else
                    {
                        ppSANEntry[offset][k++] = ch;
                        i++;
                    }
                }

                status = newExtensionAlloc(&pPkcs10Attribs->pExtensions);
                if (OK != status)
                    goto exit;

                if (OK > (status = setSubjAltNameExtension(sans, numsans, &pPkcs10Attribs->pExtensions->otherExts[pPkcs10Attribs->pExtensions->otherExtCount - 1])))
                {
                    goto exit;
                }
                /* Free the SubjectAltNameAttr array */
                if (NULL != sans)
                {
                    i = 0;
                    for (; i < numsans; i++)
                    {
                        SubjectAltNameAttr *sanattr = &sans[i];
                        if (sanattr->subjectAltNameValue.data != NULL)
                        {
                            FREE(sanattr->subjectAltNameValue.data);
                        }
                    }
                    FREE(sans);
                    sans = NULL;
                }
            }
            if ((OK != status) || ((JSON_String != token.type) && (JSON_Null != token.type) ))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_BCONS:
            if (OK == status)
            {
                if ((JSON_True == token.type))
                {
                    pPkcs10Attribs->pExtensions->hasBasicConstraints = 1;
                }
                else
                {
                    pPkcs10Attribs->pExtensions->hasBasicConstraints = 0;
                }
            }
            else
            {
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_ISCA:
            if (OK == status)
            {
                if ((JSON_True == token.type))
                {
                    pPkcs10Attribs->pExtensions->isCA = 1;
                }
                else
                {
                    pPkcs10Attribs->pExtensions->isCA = 0;
                }
            }
            else
            {
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_CERTPLEN:
            if ((OK == status) && (JSON_Integer == token.type))
            {
                pPkcs10Attribs->pExtensions->certPathLen = (sbyte)token.num.intVal;
            }
            else
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_KEYUSG:
            if ((OK == status) && (JSON_String == token.type))
            {
                char   ch  = '\0';
                ubyte2 res = 0;
                char   keyUsageVal[MAX_LINE_LENGTH];
                int    i = 0, k = 0;

                DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                while(((ubyte4)i) <= token.len)
                {
                    ch = token.pStart[i];
                    if (ch == ',' || ch == '\0' || i == token.len)
                    {
                        if (0 == DIGI_STRCMP((const sbyte *)"digitalSignature", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << digitalSignature);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"nonRepudiation", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << nonRepudiation);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"keyEncipherment", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << keyEncipherment);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"dataEncipherment", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << dataEncipherment);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"keyAgreement", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << keyAgreement);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"keyCertSign", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << keyCertSign);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"cRLSign", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << cRLSign);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"encipherOnly", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << encipherOnly);
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"decipherOnly", (const sbyte *)keyUsageVal))
                        {
                            res = res + (1 << decipherOnly);
                        }
                        DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                        k  = 0;
                        i++;
                    }
                    else if (ch == ' ')
                    {
                        i++;
                        continue;
                    }
                    else
                    {
                        keyUsageVal[k++] = ch;
                        i++;
                    }
                }

                pPkcs10Attribs->pExtensions->hasKeyUsage = TRUE;
                pPkcs10Attribs->pExtensions->keyUsage = res;
            }
            if ((OK != status) || (JSON_String != token.type))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
        case TK_CSR_ATTRIB_EXTKEYUSG:
            if ((OK == status) && (JSON_String == token.type))
            {
                char   ch  = '\0';
                char   keyUsageVal[MAX_LINE_LENGTH];
                int    i = 0, k = 0;
                extKeyUsageInfo extKeyUsage = {0};

                DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                while(((ubyte4)i) <= token.len)
                {
                    ch = token.pStart[i];
                    if (ch == ',' || ch == '\0' || i == token.len)
                    {
                        if (0 == DIGI_STRCMP((const sbyte *)"serverAuth", (const sbyte *)keyUsageVal))
                        {
                            extKeyUsage.serverAuth = TRUE;
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"clientAuth", (const sbyte *)keyUsageVal))
                        {
                            extKeyUsage.clientAuth = TRUE;
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"codeSigning", (const sbyte *)keyUsageVal))
                        {
                            extKeyUsage.codeSign = TRUE;
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"emailProtection", (const sbyte *)keyUsageVal))
                        {
                            extKeyUsage.emailProt = TRUE;
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"timeStamping", (const sbyte *)keyUsageVal))
                        {
                            extKeyUsage.timeStamp = TRUE;
                        }
                        else if (0 == DIGI_STRCMP((const sbyte *)"OCSPSigning", (const sbyte *)keyUsageVal))
                        {
                            extKeyUsage.ocspSign = TRUE;
                        }
                        DIGI_MEMSET((ubyte *)keyUsageVal, 0x00, sizeof(keyUsageVal));
                        k  = 0;
                        i++;
                    }
                    else if (ch == ' ')
                    {
                        i++;
                        continue;
                    }
                    else
                    {
                        keyUsageVal[k++] = ch;
                        i++;
                    }
                }

                status = setExtKeyUsageExtension(pPkcs10Attribs->pExtensions, &extKeyUsage);
                if (OK != status)
                    goto exit;
            }
            if ((OK != status) || ((JSON_String != token.type) && (JSON_Null != token.type) ))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }
            break;
            case TK_CSR_ATTRIB_SERIALNUMBER:
                if ( (OK == status) && (JSON_String == token.type) )
                {
                    status = CERT_ENROLL_createNameAttr(
                        (ubyte *) serialNumber_OID, 0, (ubyte *) token.pStart,
                        token.len, &pNameAttrib[attrCnt]);
                    attrCnt++;
                }
                if ((OK != status) || (JSON_String != token.type))
                {
                    status = ERR_INVALID_ARG;
                    goto exit;
                }
                break;
        }
    }

    status = CERT_ENROLL_createCertDistinguishedName(pNameAttrib, attrCnt, ppSubject);

exit:

    if (NULL != pJCtx)
    {
        (void) JSON_releaseContext(&pJCtx);
    }

    return status;
}
#endif /* __ENABLE_CERT_ENROLL_ALT_FORMATS__ */

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_getHashAlgo(ubyte4 *pHashOut, ubyte4 keyType, ubyte *pHashType, ubyte4 hashLen)
{
    MSTATUS status = OK;
    ubyte4 i;

    static DigestAlgoMap digestAlgosRSA[SUPPORTED_DIGEST_ALGO_COUNT_RSA] =
    {
        {(sbyte*)"sha1WithRSA", ht_sha1},
        {(sbyte*)"sha256WithRSA", ht_sha256},
        {(sbyte*)"sha384WithRSA", ht_sha384},
        {(sbyte*)"sha512WithRSA", ht_sha512}
    };

    static DigestAlgoMap digestAlgosECDSA[SUPPORTED_DIGEST_ALGO_COUNT_ECDSA] =
    {
        {(sbyte*)"sha256WithECDSA", ht_sha256},
        {(sbyte*)"sha384WithECDSA", ht_sha384},
        {(sbyte*)"sha512WithECDSA", ht_sha512}
    };

    if (akt_rsa == (keyType & 0xff))
    {
        for (i = 0; i < SUPPORTED_DIGEST_ALGO_COUNT_RSA; i++)
        {
            if ((hashLen == DIGI_STRLEN((const sbyte*)digestAlgosRSA[i].digestName)) &&
                    (0 == DIGI_STRNICMP((const sbyte*)digestAlgosRSA[i].digestName, (const sbyte*)pHashType, hashLen)) )
            {
                *pHashOut = digestAlgosRSA[i].digestType;
                goto exit;
            }
        }
    }
    else if (akt_ecc == (keyType & 0xff))
    {
        for (i = 0; i < SUPPORTED_DIGEST_ALGO_COUNT_ECDSA; i++)
        {
            if ((hashLen == DIGI_STRLEN((const sbyte*)digestAlgosECDSA[i].digestName)) &&
                    (0 == DIGI_STRNICMP((const sbyte*)digestAlgosECDSA[i].digestName, (const sbyte*)pHashType, hashLen)) )
            {
                *pHashOut = digestAlgosECDSA[i].digestType;
                goto exit;
            }
        }
    }
    else
    {
        status = ERR_CERT_ENROLL_UNSUPPORTED_KEY_TYPE;
        goto exit;
    }

    /* couldn't find anything at all */
    status = ERR_CERT_ENROLL_UNSUPPORTED_DIGEST;

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_getSignatureAlgorithm(CertCsrCtx *pCsrCtx, JSON_ContextType *pJCtx, ubyte4 arrNdx)
{
    MSTATUS status = OK;
    ubyte4 ndxDef = 0;
    ubyte4 ndxEval = 0;
    JSON_TokenType tokenDef = {0};
    JSON_TokenType tokenEval = {0};
    JSON_TokenType hashToken = {0};
    ubyte4 i;
    sbyte *pValue = NULL;
    byteBoolean hasDefault = FALSE;
    byteBoolean hasEval = FALSE;
    byteBoolean goBackToDefault = FALSE;
    ubyte4 valueLen = 0;

    /* if no evalFunction we can only get defaultValue */
    if (NULL == pCsrCtx->evalFunction)
    {
        status = JSON_getJsonArrayValue(pJCtx, arrNdx, "defaultValue", &ndxDef, &tokenDef, TRUE);
        if (OK != status)
            goto exit;

        hasDefault = TRUE;
    }
    else
    {
        /* Get both default and eval */
        status = JSON_getJsonArrayValue(pJCtx, arrNdx, "defaultValue", &ndxDef, &tokenDef, TRUE);
        if (OK == status)
        {
            hasDefault = TRUE;
        }
        else if (ERR_NOT_FOUND != status)
            goto exit;

        status = JSON_getJsonArrayValue(pJCtx, arrNdx, "evalValue", &ndxEval, &tokenEval, TRUE);
        if (OK == status)
        {
            hasEval = TRUE;
        }
        else if (ERR_NOT_FOUND != status)
            goto exit;

        /* We must have at least one of them to continue! */
        if (!hasDefault && !hasEval)
        {
            status = ERR_CERT_ENROLL_INVALID_CSR_ATTR_FORMAT;
            goto exit;

        }
    }

    /* try to get the first usable hash alg out of eval if we have it */
    if (hasEval)
    {
        for (i = 0; i < tokenEval.elemCnt; i++)
        {
            ndxEval++;
            status = JSON_getToken(pJCtx, ndxEval, &hashToken);
            if (OK != status)
                goto exit;

            if (JSON_String != hashToken.type)
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                goto exit;
            }

            /* see if callback supports getting the length based on the input or if we go back to default */
            status = pCsrCtx->evalFunction(pCsrCtx->pEvalFunctionArg, &goBackToDefault,
                                           (sbyte *) hashToken.pStart, hashToken.len, NULL, &valueLen);
            if (goBackToDefault) /* irregardless of status */
            {
                break;
            }
            else if (status != ERR_BUFFER_TOO_SMALL || !valueLen)
            {
                /* else just set a max length */
                valueLen = MAX_LINE_LENGTH;
            }

            /* add space for '\0' char if needbe */
            (void) DIGI_FREE((void **) &pValue);
            status = DIGI_MALLOC((void **) &pValue, valueLen + 1);
            if (OK != status)
                goto exit;

            status = pCsrCtx->evalFunction(pCsrCtx->pEvalFunctionArg, &goBackToDefault,
                                           (sbyte *) hashToken.pStart, hashToken.len, pValue, &valueLen);
            if (goBackToDefault) /* irregardless of status */
            {
                break;
            }
            else if (OK != status)
                goto exit;

            pValue[valueLen] = (sbyte) '\0';

            /* look for the first appropriate (supported) hash algo */
            status = CERT_ENROLL_getHashAlgo(&pCsrCtx->hashId, pCsrCtx->keyType, (ubyte *) pValue, valueLen);
            if (OK == status)
                goto exit; /* break */
        }
    }

    /* else try to get the first usable hash out of defaultValue */
    if (hasDefault)
    {
        for (i = 0; i < tokenDef.elemCnt; i++)
        {
            ndxDef++;
            status = JSON_getToken(pJCtx, ndxDef, &hashToken);
            if (OK != status)
                goto exit;

            if (JSON_String != hashToken.type)
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                goto exit;
            }

            /* look for the first appropriate (supported) hash algo */
            status = CERT_ENROLL_getHashAlgo(&pCsrCtx->hashId, pCsrCtx->keyType, (ubyte *) hashToken.pStart, hashToken.len);
            if (OK == status)
                goto exit; /* break */
        }
    }
    else if (goBackToDefault) /* we were told to go back to default but it was missing */
    {
        status = ERR_CERT_ENROLL_INVALID_CSR_ATTR_FORMAT;
    }

    /* otherwise status should be ERR_CERT_ENROLL_UNSUPPORTED_DIGEST if we get here */

exit:

    if (NULL != pValue)
    {
        (void) DIGI_MEMSET_FREE((ubyte **) &pValue, valueLen);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addOtherExt(
    certExtensions **ppExtensions,
    const ubyte *pOid,
    byteBoolean isCritical,
    ubyte **ppValue,
    ubyte4 valueLen)
{
    MSTATUS status;
    ubyte4 otherExtCount;
    extensions *pExt = NULL;

    /* make space for the extensions */
    if (NULL == *ppExtensions)
    {
        status = DIGI_CALLOC((void **) ppExtensions, sizeof(certExtensions), 1);
        if (OK != status)
            goto exit;
    }

    otherExtCount = (*ppExtensions)->otherExtCount + 1;

    status = DIGI_MALLOC(
        (void **) &pExt, sizeof(extensions) * otherExtCount);
    if (OK != status)
    {
        goto exit;
    }
    (void) DIGI_MEMCPY(
        pExt, (*ppExtensions)->otherExts,        sizeof(extensions) * (*ppExtensions)->otherExtCount);

    pExt[(*ppExtensions)->otherExtCount].oid = (ubyte *) pOid;
    pExt[(*ppExtensions)->otherExtCount].isCritical = isCritical;
    pExt[(*ppExtensions)->otherExtCount].value = *ppValue; *ppValue = NULL;
    pExt[(*ppExtensions)->otherExtCount].valueLen = valueLen;
    (void) DIGI_FREE((void **) &(*ppExtensions)->otherExts);

    (*ppExtensions)->otherExts = pExt;
    (*ppExtensions)->otherExtCount = otherExtCount;

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addExtensionField(
    certExtensions **ppExtensions,
    sbyte *pId,
    sbyte **ppVal)
{
    MSTATUS status = OK;

    if (0 == DIGI_STRCMP((sbyte *) "extensions.subject_directory", pId))
    {
        status = CERT_ENROLL_addOtherExt(ppExtensions, subjectDirectory_OID, FALSE, (ubyte **) ppVal, DIGI_STRLEN(*ppVal));
    }

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addValidityDate(
    TimeDate *pDate,
    sbyte *pVal)
{
    MSTATUS status = OK;

    /* internal method, null checks not necc */

    /* example "2024-04-18T20:20:20", at least 19 char */

    if (DIGI_STRLEN(pVal) < 19)
    {
        status = ERR_CERT_ENROLL_BAD_CSR_FIELD;
        goto exit;
    }

    /* set each char after the numeric value to a '\0' char */
    pVal[4] = pVal[7] = pVal[10] = pVal[13] = pVal[16] = 0;

    /* No Date validation at this point. Perhaps we add it later... */
    pDate->m_year = (ubyte2) atoi(pVal);
    pDate->m_month = (ubyte) atoi(&pVal[5]);
    pDate->m_day = (ubyte) atoi(&pVal[8]);
    pDate->m_hour = (ubyte) atoi(&pVal[11]);
    pDate->m_minute = (ubyte) atoi(&pVal[14]);
    pDate->m_second = (ubyte) atoi(&pVal[17]);

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addCsrField(
    nameAttr **ppNameAttrib,
    ubyte4 *pAttrCount,
    sbyte *pId,
    sbyte *pVal)
{
    MSTATUS status = OK;
    const sbyte *pOid = NULL;

    if (0 == DIGI_STRCMP("subject.common_name", pId))
    {
        pOid = commonName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.organization_name", pId))
    {
        pOid = organizationName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.organization_unit", pId))
    {
        pOid = organizationalUnitName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.country", pId))
    {
        pOid = countryName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.state", pId))
    {
        pOid = stateOrProvinceName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.locality", pId))
    {
        pOid = localityName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.street_address", pId))
    {
        pOid = streetAddress_OID;
    }
    else if (0 == DIGI_STRCMP("subject.postal_code", pId))
    {
        pOid = postalCode_OID;
    }
    else if (0 == DIGI_STRCMP("subject.unique_identifier", pId))
    {
        pOid = x509_uniqueIdentifier_OID;
    }
    else if (0 == DIGI_STRCMP("subject.email", pId))
    {
        pOid = pkcs9_emailAddress_OID;
    }
    else if (0 == DIGI_STRCMP("subject.domain_component", pId))
    {
        pOid = domainComponent_OID;
    }
    else if (0 == DIGI_STRCMP("subject.unstructured_name", pId))
    {
        pOid = pkcs9_unstructuredName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.unstructured_address", pId))
    {
        pOid = pkcs9_unstructuredAddress_OID;
    }
    else if (0 == DIGI_STRCMP("subject.serial_number", pId))
    {
        pOid = serialNumber_OID;
    }
    else if (0 == DIGI_STRCMP("subject.description", pId))
    {
        pOid = x509_description_OID;
    }
    else if (0 == DIGI_STRCMP("subject.dn_qualifier", pId))
    {
        pOid = dnQualifier_OID;
    }
    else if (0 == DIGI_STRCMP("subject.title", pId))
    {
        pOid = title_OID;
    }
    else if (0 == DIGI_STRCMP("subject.given_name", pId))
    {
        pOid = givenName_OID;
    }
    else if (0 == DIGI_STRCMP("subject.surname", pId))
    {
        pOid = surname_OID;
    }
    else if (0 == DIGI_STRCMP("subject.product_identifier", pId))
    {
        pOid = productIdentifier_OID;
    }
    else if (0 == DIGI_STRCMP("subject.vendor_identifier", pId))
    {
        pOid = vendorIdentifier_OID;
    }
    else
    {
        goto exit;
    }

    status = CERT_ENROLL_createNameAttr( (ubyte *) pOid, 0, (ubyte *) pVal,
                                          DIGI_STRLEN(pVal), ppNameAttrib);
    if (OK != status)
        goto exit;

    *pAttrCount = *pAttrCount + 1;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__)

static MSTATUS CERT_ENROLL_addOtherNamePermanentIdentifier(
    CertCsrCtx *pCsrCtx,
    ubyte **ppBlob,
    ubyte4 *pBlobLen)
{
    MSTATUS status;
    TAP_ObjectInfo objectInfo = {0};
    TAP_Context *pTapContext = NULL;
    TAP_EntityCredentialList *pTapEntityCredentials = NULL;
    TAP_CredentialList *pKeyCreds = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Blob certificateBlob = {0};
    sbyte4 j;
    DER_ITEMPTR pNewItem = NULL;
    DER_ITEMPTR pSeq, pTag, pTemp;
    ubyte pEkCertDigest[SHA256_RESULT_SIZE];
    ubyte pEkCertDigestHex[2*SHA256_RESULT_SIZE];
    ubyte4 len1, len2;
    pFuncPtrGetTapContext pTAPCallback;
    ubyte *pBuffer = NULL;
    ubyte4 bufferLen = 0;

    /* Get the TapContext, EntityCredentials and KeyCredentials from Client */
    if (NULL == pCsrCtx->pTAPCallback)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pTAPCallback = pCsrCtx->pTAPCallback;
    pTAPCallback(
        &pTapContext, &pTapEntityCredentials, &pKeyCreds,
        NULL, tap_key_load, 1);

    objectInfo.objectId = (TAP_ID) EK_OBJECT_ID;
    status = TAP_getRootOfTrustCertificate(
        pTapContext, &objectInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN,
        &certificateBlob, pErrContext);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == certificateBlob.blob.pBuffer)
    {
        status = ERR_TAP;
        goto exit;
    }

    /* SHA-256 digest of EK certificate */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_SHA256_completeDigest(
        certificateBlob.blob.pBuffer, certificateBlob.blob.bufferLen,
        pEkCertDigest);
#else
    status = SHA256_completeDigest(
        certificateBlob.blob.pBuffer, certificateBlob.blob.bufferLen,
        pEkCertDigest);
#endif
    if (OK != status)
    {
        goto exit;
    }

    /* Convert digest into hex string */
    for (j = sizeof(pEkCertDigest) - 1; j >= 0; j--)
    {
        pEkCertDigestHex[(2 * j) + 1] = returnHexDigit(pEkCertDigest[j]);
        pEkCertDigestHex[2 * j] = returnHexDigit(pEkCertDigest[j] >> 4);
    }

    /* Construct OtherName permanent identifier defined as per
     * https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
     * section 8
     *
     *     id-on-permanentIdentifier OBJECT IDENTIFIER ::= { id-on 3}
     *     PermanentIdentifier ::= SEQUENCE {
     *         identifierValue UTF8String
     *         assigner OBJECT IDENTIFIER OPTIONAL
     *     }
     *
     * Construct OtherName as follows
     * - OtherName type-id: id-on-permanentIdentifier
     * - OtherName value: PermanentIdentifier
     *
     *     SEQUENCE
     *         OID (id-on-permanentIdentifier - 1.3.6.1.5.5.7.8.3)
     *         [0] (EXPLICIT TAG)
     *             SEQUENCE
     *                 UTF8STRING (identifierValue - SHA256 EK certificate)
     *                 OID (tcg-on-ekPermIdSha256 - 2.23.133.12.1)
     */
    status = DER_AddSequence(NULL, &pNewItem);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddOID(pNewItem, id_on_permanentIdentifier_OID, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddTag(pNewItem, 0, &pTag);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddSequence(pTag, &pSeq);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pSeq, UTF8STRING, sizeof(pEkCertDigestHex), pEkCertDigestHex, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddOID(pSeq, tcg_on_ekPermIdSha256_OID, NULL);
    if (OK != status)
    {
        goto exit;
    }

    /* Caller constructs ASN1 element which contains the OtherName
     * type-id and value, only serialize and return subelements here */
    pTemp = DER_FIRST_CHILD(pNewItem);
    status = DER_GetLength(pTemp, &len1);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_GetLength(DER_NEXT_SIBLING(pTemp), &len2);
    if (OK != status)
    {
        goto exit;
    }

    bufferLen = len1 + len2;
    status = DIGI_MALLOC((void **) &pBuffer, bufferLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_SerializeInto(pTemp, pBuffer, &len1);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_SerializeInto(
        DER_NEXT_SIBLING(pTemp), pBuffer + len1, &len2);
    if (OK != status)
    {
        goto exit;
    }

    *ppBlob = pBuffer; pBuffer = NULL;
    *pBlobLen = bufferLen;

exit:

    if (NULL != pBuffer)
    {
        DIGI_FREE((void **) &pBuffer);
    }

    if (NULL != pNewItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pNewItem);
    }

    TAP_UTILS_freeBlob(&certificateBlob);

    if (NULL != pTapContext)
    {
        pTAPCallback(
            &pTapContext, &pTapEntityCredentials, &pKeyCreds,
            NULL, tap_key_load, 0);
    }

    return status;
}

static MSTATUS CERT_ENROLL_tpmManufacturerCb(
    struct ASN1_ITEM *pItem, CStream cs, void *pUserArg)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pIter, pAttr, pVal;
    ASN1_ITEMPTR *ppBuffer = (ASN1_ITEMPTR *) pUserArg;

    /* DirectoryName tag */
    if (4 == pItem->tag)
    {
        pIter = ASN1_FIRST_CHILD(pItem);
        if (NULL == pIter)
            goto exit;

        while (NULL != pIter)
        {
            if (OK == ASN1_VerifyType(pIter, SEQUENCE))
            {
                pAttr = ASN1_FIRST_CHILD(pIter);
                while (NULL != pAttr)
                {
                    if (OK == ASN1_VerifyType(pAttr, MOC_SET))
                    {
                        pVal = ASN1_FIRST_CHILD(pAttr);
                        if (NULL != pVal)
                        {
                            if (OK == ASN1_VerifyType(pVal, SEQUENCE))
                            {
                                pVal = ASN1_FIRST_CHILD(pVal);
                                if (NULL != pVal)
                                {
                                    if (OK == ASN1_VerifyOID(pVal, cs, tcg_at_tpmManufacturer_OID))
                                    {
                                        /* Found TPM manufacturer */
                                        pVal = ASN1_NEXT_SIBLING(pVal);
                                        if (NULL == pVal)
                                        {
                                            status = ERR_INVALID_ARG;
                                            goto exit;
                                        }

                                        status = ASN1_VerifyType(pVal, UTF8STRING);
                                        if (OK != status)
                                        {
                                            goto exit;
                                        }

                                        *ppBuffer = pVal;
                                        goto exit;
                                    }
                                }
                            }
                        }
                    }

                    pAttr = ASN1_NEXT_SIBLING(pAttr);
                }
            }

            pIter = ASN1_NEXT_SIBLING(pItem);
        }
    }

exit:

    return status;
}

static MSTATUS CERT_ENROLL_addOtherNameHardwareModuleName(
    CertCsrCtx *pCsrCtx,
    ubyte **ppBlob,
    ubyte4 *pBlobLen)
{
    MSTATUS status;
    TAP_ObjectInfo objectInfo = {0};
    TAP_Context *pTapContext = NULL;
    TAP_EntityCredentialList *pTapEntityCredentials = NULL;
    TAP_CredentialList *pKeyCreds = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Blob certificateBlob = {0};
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pCertItem = NULL;
    ASN1_ITEMPTR pTpmManufacturer = NULL;
    ASN1_ITEMPTR pExtensions = NULL;
    intBoolean isCritical = FALSE;
    ASN1_ITEMPTR pAKI = NULL;
    ASN1_ITEMPTR pSerial = NULL;
    ubyte4 hwSerialNumLen;
    ubyte *pHwSerialNum = NULL;
    ubyte *pIter;
    sbyte4 i, j;
    DER_ITEMPTR pNewItem = NULL;
    DER_ITEMPTR pSeq, pTag, pTemp;
    ubyte4 len1, len2;
    pFuncPtrGetTapContext pTAPCallback;
    ubyte *pBuffer = NULL;
    ubyte4 bufferLen = 0;

    /* Get the TapContext, EntityCredentials and KeyCredentials from Client */
    if (NULL == pCsrCtx->pTAPCallback)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pTAPCallback = pCsrCtx->pTAPCallback;
    pTAPCallback(
        &pTapContext, &pTapEntityCredentials, &pKeyCreds,
        NULL, tap_key_load, 1);

    /* Get EK certificate */
    objectInfo.objectId = (TAP_ID) EK_OBJECT_ID;
    status = TAP_getRootOfTrustCertificate(
        pTapContext, &objectInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN,
        &certificateBlob, pErrContext);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == certificateBlob.blob.pBuffer)
    {
        status = ERR_TAP;
        goto exit;
    }

    MF_attach(&mf, certificateBlob.blob.bufferLen, certificateBlob.blob.pBuffer);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pCertItem);
    if (OK != status)
    {
        goto exit;
    }

    /* Get TPM manufacturer from the EK certificate */
    status = X509_enumerateAltName(
        ASN1_FIRST_CHILD(pCertItem), cs, TRUE, CERT_ENROLL_tpmManufacturerCb,
        &pTpmManufacturer);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == pTpmManufacturer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Get Authority Key Identifier from the EK certificate */
    status = X509_getCertificateExtensions(
        ASN1_FIRST_CHILD(pCertItem), &pExtensions);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == pExtensions)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = X509_getCertExtension(
        pExtensions, cs, authorityKeyIdentifier_OID, &isCritical,
        &pAKI);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == pAKI)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ASN1_VerifyType(pAKI, SEQUENCE);
    if (OK != status)
    {
        goto exit;
    }

    pAKI = ASN1_FIRST_CHILD(pAKI);
    if (NULL == pAKI)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Get the serial number from the EK certificate */
    status = X509_getCertificateIssuerSerialNumber(
        ASN1_FIRST_CHILD(pCertItem), NULL, &pSerial);
    if (OK != status)
    {
        goto exit;
    }

    /* Construct OtherName hardware module name defined as per
     * https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
     * section 8
     *
     *     id-on-hardwareModuleName OBJECT IDENTIFIER ::= iso(1) identified-organization(3) dod(6)
internet(1) security(5) mechanisms(5) pkix(7) on(8) 4
     *     HardwareModuleName ::= SEQUENCE {
     *         hwType OBJECT IDENTIFIER
     *         hwSerialNum OCTET STRING
     *     }
     *
     * Construct OtherName as follows
     * - OtherName type-id: id-on-hardwareModuleName
     * - OtherName value: HardwareModuleName
     *
     *     SEQUENCE
     *         OID (id-on-hardwareModuleName - 1.3.6.1.5.5.7.8.4)
     *         [0] (EXPLICIT TAG)
     *             SEQUENCE
     *                 OID (hwType - 2.23.133.1.2)
     *                 OCTETSTRING (hwSerialNum - <TPM Manufacturer>:<EK Certificate Authority Key Identifier>:<EK Certificate Serial Number>)
     */
    hwSerialNumLen = pTpmManufacturer->length + 1 + (pAKI->length * 2) + 1 + (pSerial->length * 2);
    status = DIGI_MALLOC((void **) &pHwSerialNum, hwSerialNumLen);
    if (OK != status)
    {
        goto exit;
    }

    pIter = pHwSerialNum;

    DIGI_MEMCPY(
        pIter, certificateBlob.blob.pBuffer + pTpmManufacturer->dataOffset,
        pTpmManufacturer->length);
    pIter += pTpmManufacturer->length;

    *pIter = ':';
    pIter++;

    for (j = pAKI->length - 1; j >= 0; j--)
    {
        pIter[(2 * j) + 1] = returnHexDigit(certificateBlob.blob.pBuffer[pAKI->dataOffset + j]);
        pIter[2 * j] = returnHexDigit(certificateBlob.blob.pBuffer[pAKI->dataOffset + j] >> 4);
    }
    pIter += (pAKI->length * 2);

    *pIter = ':';
    pIter++;

    for (j = pSerial->length - 1; j >= 0; j--)
    {
        pIter[(2 * j) + 1] = returnHexDigit(certificateBlob.blob.pBuffer[pSerial->dataOffset + j]);
        pIter[2 * j] = returnHexDigit(certificateBlob.blob.pBuffer[pSerial->dataOffset + j] >> 4);
    }

    /* Caller constructs ASN1 element which contains the OtherName
     * type-id and value, only serialize and return subelements here */
    status = DER_AddSequence(NULL, &pNewItem);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddOID(pNewItem, id_on_hardwareModuleName_OID, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddTag(pNewItem, 0, &pTag);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddSequence(pTag, &pSeq);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddOID(pSeq, tcg_at_hwType_OID, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddItem(
        pSeq, OCTETSTRING, hwSerialNumLen, pHwSerialNum, NULL);
    if (OK != status)
    {
        goto exit;
    }

    pTemp = DER_FIRST_CHILD(pNewItem);
    status = DER_GetLength(pTemp, &len1);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_GetLength(DER_NEXT_SIBLING(pTemp), &len2);
    if (OK != status)
    {
        goto exit;
    }

    bufferLen = len1 + len2;
    status = DIGI_MALLOC((void **) &pBuffer, bufferLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_SerializeInto(pTemp, pBuffer, &len1);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_SerializeInto(
        DER_NEXT_SIBLING(pTemp), pBuffer + len1, &len2);
    if (OK != status)
    {
        goto exit;
    }

    *ppBlob = pBuffer; pBuffer = NULL;
    *pBlobLen = bufferLen;

exit:

    if (NULL != pBuffer)
    {
        DIGI_FREE((void **) &pBuffer);
    }

    if (NULL != pNewItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pNewItem);
    }

    if (NULL != pHwSerialNum)
    {
        DIGI_FREE((void **) &pHwSerialNum);
    }

    if (NULL != pCertItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pCertItem);
    }

    TAP_UTILS_freeBlob(&certificateBlob);

    if (NULL != pTapContext)
    {
        pTAPCallback(
            &pTapContext, &pTapEntityCredentials, &pKeyCreds,
            NULL, tap_key_load, 0);
    }

    return status;
}

extern MSTATUS CERT_ENROLL_setTAPCallback(
    CertCsrCtx *pCsrCtx,
    pFuncPtrGetTapContext pTAPCallback)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL != pCsrCtx)
    {
        pCsrCtx->pTAPCallback = pTAPCallback;
        status = OK;
    }

    return status;
}

#endif

static MSTATUS CERT_ENROLL_setCertificatePolicy(
    certExtensions **ppExtensions, ubyte **ppPolicyOids)
{
    MSTATUS status;
    ubyte *pDer = NULL;
    ubyte4 derLen = 0;
    DER_ITEMPTR pSeq = NULL;
    DER_ITEMPTR pPolicy = NULL;
    extensions *pCertPolicy;

    status = newExtensionAlloc(ppExtensions);
    if (OK != status)
    {
        goto exit;
    }

    status = DER_AddSequence(NULL, &pSeq);
    if (OK != status)
    {
        goto exit;
    }

    while (NULL != *ppPolicyOids)
    {
        status = DER_AddSequence(pSeq, &pPolicy);
        if (OK != status)
        {
            goto exit;
        }

        status = DER_AddOID(pPolicy, *ppPolicyOids, 0);
        if (OK != status)
        {
            goto exit;
        }

        ppPolicyOids++;
    }

    status = DER_Serialize(pSeq, &pDer, &derLen);
    if (OK != status)
    {
        goto exit;
    }

    pCertPolicy = &((*ppExtensions)->otherExts[(*ppExtensions)->otherExtCount-1]);
    pCertPolicy->oid = (ubyte *) certificatePolicies_OID;
    pCertPolicy->isCritical = FALSE;
    pCertPolicy->value = pDer;
    pCertPolicy->valueLen = derLen;

exit:

    if (NULL != pSeq)
    {
        TREE_DeleteTreeItem((TreeItem *) pSeq);
    }

    return status;
}

static MSTATUS CERT_ENROLL_addCsrSANField(
    CertCsrCtx *pCsrCtx,
    DER_ITEMPTR *ppRoot,
    byteBoolean *pIsCritical,
    sbyte *pId,
    sbyte **ppValue)
{
    MSTATUS status = OK;
    DER_ITEMPTR pRoot = *ppRoot;
    sbyte *pVal = *ppValue;
    ubyte *pIpAddr = NULL;
    ubyte4 ipAddrLen = 0;
    byteBoolean w;
    ubyte *pOid = NULL;
    ubyte *pRawOid = NULL;
    ubyte4 rawOidLen = 0;
#if defined(__ENABLE_DIGICERT_TAP__)
    ubyte *pBlob = NULL;
    ubyte4 blobLen = 0;
#else
    MOC_UNUSED(pCsrCtx);
#endif
    nameAttr *ppKeyGenNameAttr[1] = { 0 };
    DER_ITEMPTR pKeyGenAttr = NULL;
    certDistinguishedName *pKeyGenDN = NULL;
    ubyte *pTmp = NULL;
    ubyte4 tmpLen = 0;
    byteBoolean allocRoot = FALSE;

    /* internal method, NULL checks not necc */

    if (NULL == pRoot)
    {
        status = DER_AddSequence(NULL, &pRoot);
        if (OK != status)
            goto exit;

        allocRoot = TRUE;
    }

    if (0 == DIGI_STRCMP((sbyte *) "san.critical", pId))
    {
        if(0 == DIGI_STRCMP((sbyte *) "true", pVal))
        {
            *pIsCritical = TRUE;
        }
        else if(0 == DIGI_STRCMP((sbyte *) "false", pVal))
        {
            *pIsCritical = FALSE;
        }
        else
        {
            status = ERR_CERT_ENROLL_BAD_CSR_FIELD;
        }
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.dns_name", pId))
    {
        status = DER_AddItemOwnData(pRoot, (PRIMITIVE|CONTEXT|SubjectAltName_dNSName),
            DIGI_STRLEN(pVal), (ubyte **) &pVal, NULL);
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.ip_address", pId))
    {
        /* Max IP address is IPv6 at 16 bytes */
        status = DIGI_MALLOC((void **) &pIpAddr, 16);
        if (OK != status)
            goto exit;

        status = CA_MGMT_convertIpAddress(pVal, pIpAddr, &ipAddrLen);
        if (OK != status)
            goto exit;

        status = DER_AddItemOwnData(pRoot, (PRIMITIVE|CONTEXT|SubjectAltName_iPAddress),
            ipAddrLen, &pIpAddr, NULL);
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.email", pId))
    {
        status = DER_AddItemOwnData(pRoot, (PRIMITIVE|CONTEXT|SubjectAltName_rfc822Name),
            DIGI_STRLEN(pVal), (ubyte **) &pVal, NULL);
    }
    else if (0 == DIGI_STRCMP((sbyte *)"san.uri", pId))
    {
        status = DER_AddItemOwnData(pRoot, (PRIMITIVE|CONTEXT|SubjectAltName_uniformResourceIdentifier),
            DIGI_STRLEN(pVal), (ubyte **) &pVal, NULL);
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.registered_id", pId))
    {
        status = BEREncodeOID(pVal, &w, &pOid);
        if (OK != status)
            goto exit;

        rawOidLen = (*(pOid + 1));
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pRawOid, rawOidLen, pOid + 2, rawOidLen);
        if (OK != status)
            goto exit;

        status = DER_AddItemOwnData(pRoot, (PRIMITIVE|CONTEXT|SubjectAltName_registeredID),
            rawOidLen, &pRawOid, NULL);
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.other_name.permanent_identifier", pId))
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        status = CERT_ENROLL_addOtherNamePermanentIdentifier(
            pCsrCtx, &pBlob, &blobLen);
        if (OK != status)
        {
            goto exit;
        }

        status = DER_AddItemOwnData(pRoot, (CONSTRUCTED|CONTEXT|SubjectAltName_otherName), blobLen, &pBlob, NULL);
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.other_name.hardware_module_name", pId))
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        status = CERT_ENROLL_addOtherNameHardwareModuleName(
            pCsrCtx, &pBlob, &blobLen);
        if (OK != status)
        {
            goto exit;
        }

        status = DER_AddItemOwnData(pRoot, (CONSTRUCTED|CONTEXT|SubjectAltName_otherName), blobLen, &pBlob, NULL);
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.other_name", pId))
    {
        status = DER_AddItemOwnData(pRoot, (PRIMITIVE|CONTEXT|SubjectAltName_otherName),
            DIGI_STRLEN(pVal), (ubyte **) &pVal, NULL);
    }
    else if (0 == DIGI_STRCMP((sbyte *) "san.directory_name.key_algorithm", pId))
    {
        CERT_ENROLL_createNameAttr((ubyte *) commonName_OID, 0, (ubyte *) pVal, DIGI_STRLEN(pVal), ppKeyGenNameAttr);

        status = CERT_ENROLL_createCertDistinguishedName(ppKeyGenNameAttr, 1, &pKeyGenDN);
        if (OK != status)
        {
            goto exit;
        }

        status = DER_AddTag(NULL, (PRIMITIVE|CONTEXT|SubjectAltName_directoryName), &pKeyGenAttr);
        if (OK != status)
        {
            goto exit;
        }

        status = ASN1CERT_StoreDistinguishedName(pKeyGenAttr, pKeyGenDN);
        if (OK != status)
        {
            goto exit;
        }

        status = DER_Serialize(pKeyGenAttr, &pTmp, &tmpLen);
        if (OK != status)
        {
            goto exit;
        }

        status = DER_AddDERBufferOwn(pRoot, tmpLen, (const ubyte **) &pTmp, NULL);
    }
    if (OK != status)
        goto exit;

    /* set the output pointers back */
    *ppValue = pVal;
    *ppRoot = pRoot; pRoot = NULL;

exit:

    if (allocRoot && NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }
    if (NULL != pIpAddr)
    {
        DIGI_FREE((void **) &pIpAddr);
    }
    if (NULL != pRawOid)
    {
        DIGI_FREE((void **) &pRawOid);
    }

    TREE_DeleteTreeItem((TreeItem *) pKeyGenAttr);

    DIGI_FREE((void **) &pTmp);

    CA_MGMT_freeCertDistinguishedName(&pKeyGenDN);

#if defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != pBlob)
    {
        DIGI_FREE((void **) &pBlob);
    }
#endif

    if (NULL != pOid)
    {
        DIGI_FREE((void **) &pOid);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addKeyUsageField(
    ubyte2 *pKeyUsage,
    byteBoolean *pIsCritical,
    ubyte4 keyType,
    sbyte *pId,
    sbyte *pVal
)
{
    MSTATUS status = OK;

    /* internal method, NULL checks not necc */
    if (0 == DIGI_STRCMP((sbyte *) "key_usage.critical", pId))
    {
        if (0 == DIGI_STRCMP((sbyte *) "yes", pVal))
        {
            *pIsCritical = TRUE;
        }
        else if (0 == DIGI_STRCMP((sbyte *) "no", pVal))
        {
            *pIsCritical = FALSE;
        }
        else
        {
            status = ERR_CERT_ENROLL_BAD_KEY_USAGE_VAL;
        }
    }
    else if (0 == DIGI_STRCMP((sbyte *) "key_usage.rsa_additional_values", pId))
    {
        if (akt_rsa == (keyType & 0xff))
        {
            if (0 == DIGI_STRCMP((sbyte *) "digital_signature", pVal))
            {
                *pKeyUsage |= (1 << digitalSignature);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "non_repudiation", pVal))
            {
                *pKeyUsage |= (1 << nonRepudiation);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "key_encipherment", pVal))
            {
                *pKeyUsage |= (1 << keyEncipherment);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "data_encipherment", pVal))
            {
                *pKeyUsage |= (1 << dataEncipherment);
            }
            else
            {
                status = ERR_CERT_ENROLL_BAD_KEY_USAGE_VAL;
            }
        }
    }
    else if (0 == DIGI_STRCMP((sbyte *) "key_usage.ecdsa_additional_values", pId))
    {
        if (akt_ecc == (keyType & 0xff))
        {
            if (0 == DIGI_STRCMP((sbyte *) "digital_signature", pVal))
            {
                *pKeyUsage |= (1 << digitalSignature);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "non_repudiation", pVal))
            {
                *pKeyUsage |= (1 << nonRepudiation);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "key_agreement", pVal))
            {
                *pKeyUsage |= (1 << keyAgreement);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "encipher_only", pVal))
            {
                *pKeyUsage |= (1 << encipherOnly);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "decipher_only", pVal))
            {
                *pKeyUsage |= (1 << decipherOnly);
            }
            else
            {
                status = ERR_CERT_ENROLL_BAD_KEY_USAGE_VAL;
            }
        }
    }
    else if (0 == DIGI_STRCMP((sbyte *) "key_usage.ed25519_additional_values", pId) ||
             0 == DIGI_STRCMP((sbyte *) "key_usage.ed448_additional_values", pId))
    {
        if (akt_ecc_ed == (keyType & 0xff))
        {
            if (0 == DIGI_STRCMP((sbyte *) "digital_signature", pVal))
            {
                *pKeyUsage |= (1 << digitalSignature);
            }
            else if (0 == DIGI_STRCMP((sbyte *) "non_repudiation", pVal))
            {
                *pKeyUsage |= (1 << nonRepudiation);
            }
            else
            {
                status = ERR_CERT_ENROLL_BAD_KEY_USAGE_VAL;
            }
        }
    }

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addExtendedKeyUsageField(
    DER_ITEMPTR *ppRoot,
    byteBoolean *pIsCritical,
    sbyte *pId,
    sbyte *pVal
)
{
    MSTATUS status = OK;
    DER_ITEMPTR pRoot = *ppRoot;

    /* internal method, NULL checks not necc */

    if (NULL == pRoot)
    {
        status = DER_AddSequence(NULL, &pRoot);
        if (OK != status)
            goto exit;
    }

    if (0 == DIGI_STRCMP((sbyte *) "extended_key_usage.critical", pId))
    {
        if (0 == DIGI_STRCMP((sbyte *) "yes", pVal))
        {
            *pIsCritical = TRUE;
        }
        else if (0 == DIGI_STRCMP((sbyte *) "no", pVal))
        {
            *pIsCritical = FALSE;
        }
        else
        {
            status = ERR_CERT_ENROLL_BAD_EXT_KEY_USAGE_VAL;
        }
    }
    else if (0 == DIGI_STRCMP((sbyte *) "extended_key_usage.additional_values", pId))
    {
        if (0 == DIGI_STRCMP((sbyte *)"server_authentication", pVal))
        {
            status = DER_AddOID(pRoot, id_kp_serverAuth_OID, 0);
        }
        else if (0 == DIGI_STRCMP((sbyte *)"client_authentication", pVal))
        {
            status = DER_AddOID(pRoot, id_kp_clientAuth_OID, 0);
        }
        else if (0 == DIGI_STRCMP((sbyte *)"code_signing", pVal))
        {
            status = DER_AddOID(pRoot, id_kp_codeSigning_OID, 0);
        }
        else if (0 == DIGI_STRCMP((sbyte *)"email_protection", pVal))
        {
            status = DER_AddOID(pRoot, id_kp_emailProtection_OID, 0);
        }
        else if (0 == DIGI_STRCMP((sbyte *)"smart_card_logon", pVal))
        {
            status = DER_AddOID(pRoot, id_kp_smartCardLogon_OID, 0);
        }
        else
        {
            status = ERR_CERT_ENROLL_BAD_EXT_KEY_USAGE_VAL;
        }
    }
    else
    {
        if (pRoot != *ppRoot)
        {
            TREE_DeleteTreeItem((TreeItem *) pRoot);
        }
        goto exit;
    }

    /* set pointer back */
    *ppRoot = pRoot;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static void CERT_ENROLL_convertStringToByteArray(sbyte *pIn, sbyte4 inLen, ubyte *pResults, ubyte4* pCount)
{
    ubyte4 i = 0;

    /* internal method, null checks not necc */
    while (inLen > 0)
    {
        sscanf((char *) pIn, "%02X", (unsigned int *) &pResults[i]);
        i++;
        inLen -= 3;
        pIn += 3;
    }
    *pCount = i;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_convertStringToBmpByteArray(sbyte *pIn, ubyte4 inLen, ubyte *pResults, ubyte4 *pCount)
{
    MSTATUS status = OK;
    ubyte4 i=0, j=0;
    ubyte4 len = 2 * inLen;
    if (len == 0)
    {
        pResults[0] = 0;
        *pCount = 0;
        goto exit;
    }
    if (len > MAX_ASN1_BMPSTRING)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }
    for (i = 0; i < len - 1; i += 2, j++)
    {
        pResults[i] = 0;
        pResults[i+1] = (ubyte) pIn[j];
    }

    *pCount = len;

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addExtAttr(extensions *pExtension, JSON_ContextType *pJCtx,
                                      ubyte4 outerNdx, JSON_TokenType *pOuterToken)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    DER_ITEMPTR pParent = NULL;
    ubyte4 arrNdx = 0;
    JSON_TokenType arrToken = {0}, token = {0};
    sbyte *pOidStr = NULL;
    ubyte *pOid = NULL;
    ubyte *pValue[MAX_ASN1_OBJECTS] = {0};
    ubyte4 index = 0;
    intBoolean isCritical = FALSE;
    byteBoolean w;

    MOC_UNUSED(pOuterToken);

    status = JSON_getJsonStringValue(pJCtx, outerNdx, "oid", &pOidStr, TRUE);
    if (OK != status)
        goto exit;

    status = BEREncodeOID(pOidStr, &w, &pOid);
    if (OK != status)
        goto exit;

    status = JSON_getJsonArrayValue(pJCtx, outerNdx, "tlv", &arrNdx, &arrToken, TRUE);
    if (OK != status)
        goto exit;

    arrNdx++;
    for (i = 0; i < arrToken.elemCnt; i++)
    {
        status = JSON_getToken(pJCtx, arrNdx + i, &token);
        if (OK != status)
            goto exit;

        if (JSON_String != token.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        /* compare the beginning of the string to the possible types */
        if (0 == DIGI_STRNCMP((sbyte *) token.pStart, (sbyte *) "SEQUENCE", 8))
        {
            /* there should be nothing after SEQUENCE */
            if (token.len != 8)
            {
                status = ERR_CERT_ENROLL_INVALID_EXT_ATTR_FORMAT;
                goto exit;
            }

            if(NULL == pParent)
            {
                status = DER_AddSequence(NULL, &pParent);
            }
            else
            {
                status = DER_AddSequence(pParent, NULL);
            }
        }
        else if (0 == DIGI_STRNCMP(token.pStart, (sbyte *) "INTEGER", 7))
        {
            ubyte value[160] = {0};
            ubyte4 count = 0;

            /* there should be a space and value after INTEGER */
            if (token.len < 9 || ' ' != (char) token.pStart[7])
            {
                status = ERR_CERT_ENROLL_INVALID_EXT_ATTR_FORMAT;
                goto exit;
            }

            CERT_ENROLL_convertStringToByteArray((sbyte *) token.pStart + 7, token.len - 7, &value[0], &count);
            if(NULL == pParent)
            {
                status = DER_AddItem(NULL, INTEGER, count, value, &pParent);
            }
            else
            {
                status = DER_AddItem(pParent, INTEGER, count, value, NULL);
            }
        }
        else if (0 == DIGI_STRNCMP(token.pStart, (sbyte *) "IA5STRING", 9))
        {
            /* there should be a space and value after IA5STRING */
            if (token.len < 11 || ' ' != (char) token.pStart[9])
            {
                status = ERR_CERT_ENROLL_INVALID_EXT_ATTR_FORMAT;
                goto exit;
            }

            if(NULL == pParent)
            {
                status = DER_AddItem(NULL, IA5STRING, token.len - 10, (ubyte *) token.pStart + 10, &pParent);
            }
            else
            {
                status = DER_AddItem(pParent, IA5STRING, token.len - 10, (ubyte *) token.pStart + 10, NULL);
            }
        }
        else if (0 == DIGI_STRNCMP(token.pStart, (sbyte *) "UTF8STRING", 10))
        {
            /* there should be a space and value after UTF8STRING */
            if (token.len < 12 || ' ' != (char) token.pStart[10])
            {
                status = ERR_CERT_ENROLL_INVALID_EXT_ATTR_FORMAT;
                goto exit;
            }

            if(NULL == pParent)
            {
                status = DER_AddItem(NULL, UTF8STRING, token.len - 11, (ubyte *) token.pStart + 11, &pParent);
            }
            else
            {
                status = DER_AddItem(pParent, UTF8STRING, token.len - 11, (ubyte *) token.pStart + 11, NULL);
            }
        }
        else if (0 == DIGI_STRNCMP(token.pStart, (sbyte *) "BMPSTRING", 9))
        {
            ubyte4 count = 0;

            /* there should be a space and value after BMPSTRING */
            if (token.len < 11 || ' ' != (char) token.pStart[9])
            {
                status = ERR_CERT_ENROLL_INVALID_EXT_ATTR_FORMAT;
                goto exit;
            }

            status = DIGI_CALLOC((void **) &pValue[index], 1, MAX_ASN1_BMPSTRING);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_convertStringToBmpByteArray((sbyte *) token.pStart + 10, token.len - 10, pValue[index], &count);
            if (OK != status)
            {
                /* increase index so it's correct on error */
                index++;
                goto exit;
            }

            if(NULL == pParent)
            {
                status = DER_AddItemCopyData(NULL, BMPSTRING, count, pValue[index], &pParent);
            }
            else
            {
                status = DER_AddItemCopyData(pParent, BMPSTRING, count, pValue[index], NULL);
            }
            index++;
        }
        else if (0 == DIGI_STRNCMP(token.pStart, (sbyte *) "BITSTRING", 9))
        {
            ubyte4 count = 0;
            /* there should be a space and value after BITSTRING */
            if (token.len < 11 || ' ' != (char) token.pStart[9])
            {
                status = ERR_CERT_ENROLL_INVALID_EXT_ATTR_FORMAT;
                goto exit;
            }

            status = DIGI_CALLOC((void **) &pValue[index], 1, MAX_ASN1_BITSTRING);
            if (OK != status)
                goto exit;

            CERT_ENROLL_convertStringToByteArray((sbyte *) token.pStart + 9, token.len - 9, pValue[index], &count);

            if(NULL == pParent)
            {
                status = DER_AddBitString(NULL, count, pValue[index], &pParent);
            }
            else
            {
                status = DER_AddBitString(pParent, count, pValue[index], NULL);
            }
            index++;
        }
        else
        {
            status = ERR_CERT_ENROLL_INVALID_EXT_ATTR_FORMAT;
        }
        if (OK != status)
            goto exit;
    }

    status = JSON_getJsonBooleanValue(pJCtx, outerNdx, "critical", &isCritical, TRUE);
    if (ERR_NOT_FOUND == status)
    {
        status = OK;
    }
    if (OK != status)
        goto exit;

    pExtension->oid = (ubyte*) pOid + 1; pOid = NULL;
    pExtension->isCritical = isCritical;

    status = DER_Serialize(pParent, &pExtension->value, &pExtension->valueLen);

exit:

    for (i = 0; i < index; i++)
    {
        if (NULL != pValue[i])
        {
            (void) DIGI_FREE((void **) &pValue[i]);
        }
    }

    if (NULL != pOid)
    {
        (void) DIGI_FREE((void **) &pOid);
    }

    if (NULL != pOidStr)
    {
        (void) DIGI_FREE((void **) &pOidStr);
    }

    if (NULL != pParent)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pParent);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addExtAttrs(certExtensions **ppExtensions, JSON_ContextType *pJCtx,
                                       ubyte4 outerNdx, JSON_TokenType *pOuterToken)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    JSON_TokenType token = {0};

    /* internal method, NULL checks not necc, pOuterToken->elemCnt already checked */

    for (; i < pOuterToken->elemCnt; i++)
    {
        status = JSON_getToken(pJCtx, outerNdx, &token);
        if (OK != status)
            goto exit;

        if (JSON_Object != token.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        status = newExtensionAlloc(ppExtensions);
        if (OK != status)
            goto exit;

        status = CERT_ENROLL_addExtAttr(&((*ppExtensions)->otherExts[(*ppExtensions)->otherExtCount-1]), pJCtx, outerNdx, &token);
        if (OK != status)
            goto exit;

        status = JSON_getLastIndexInObject(pJCtx, outerNdx, &outerNdx);
        if (OK != status)
            goto exit;

        outerNdx++;
    }

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_getJsonStringValueWithEval(JSON_ContextType *pJCtx, ubyte4 arrNdx, CertCsrCtx *pCsrCtx, sbyte **ppValue)
{
    MSTATUS status = OK;
    sbyte *pTemp = NULL;
    sbyte *pValue = NULL;
    ubyte4 outLen = 0;
    byteBoolean goBackToDefault = FALSE;
    ubyte4 ndxDef = 0, i;
    JSON_TokenType tokenDef = {0};
    JSON_TokenType valToken = {0};

    /* try to use the evalFunction if possible */
    if (NULL != pCsrCtx->evalFunction)
    {
        status = JSON_getJsonStringValue(pJCtx, arrNdx, "evalValue", &pTemp, TRUE);
        if (ERR_NOT_FOUND == status)
        {
            goto useDefault;
        }
        else if (OK != status)
            goto exit;

        /* see if callback supports getting the length based on the input */
        status = pCsrCtx->evalFunction(pCsrCtx->pEvalFunctionArg, &goBackToDefault,
                                       pTemp, DIGI_STRLEN(pTemp), NULL, &outLen);
        if (goBackToDefault) /* irregardless of status */
        {
            goto useDefault;
        }
        else if (status != ERR_BUFFER_TOO_SMALL || !outLen)
        {
            /* else just set a max length */
            outLen = MAX_LINE_LENGTH;
        }

        /* add space for '\0' char if needbe */
        status = DIGI_MALLOC((void **) &pValue, outLen + 1);
        if (OK != status)
            goto exit;

        status = pCsrCtx->evalFunction(pCsrCtx->pEvalFunctionArg, &goBackToDefault,
                                       pTemp, DIGI_STRLEN(pTemp), pValue, &outLen);
        if (goBackToDefault) /* irregardless of status */
        {
            /* free pValue now as it might be allocated again when we get the default value */
            (void) DIGI_FREE((void **) &pValue);
            goto useDefault;
        }
        else if (OK != status)
            goto exit;

        pValue[outLen] = (sbyte) '\0';
        *ppValue = pValue; pValue = NULL;
        goto exit;
    }

useDefault:

    status = JSON_getJsonArrayValue(pJCtx, arrNdx, "defaultValue", &ndxDef, &tokenDef, TRUE);
    if (ERR_NOT_FOUND == status) /* change to a more descriptive error code */
    {
        status = OK;
        goto exit;
    }
    else if (OK != status)
        goto exit;

    if (0 == tokenDef.elemCnt)
    {
        status = ERR_CERT_ENROLL_INVALID_CSR_ATTR_FORMAT;
        goto exit;
    }

    for (i = 0; i < tokenDef.elemCnt; i++)
    {
        ndxDef++;
        status = JSON_getToken(pJCtx, ndxDef, &valToken);
        if (OK != status)
            goto exit;

        if (JSON_String != valToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY(
            (void **) &pValue, valToken.len + 1,
            (sbyte *) valToken.pStart, valToken.len);
        if (OK != status)
            goto exit;

        pValue[valToken.len] = (sbyte) '\0';

        /* Always use the first one */
        break;
    }

    *ppValue = pValue; pValue = NULL;

exit:

    if (NULL != pTemp)
    {
        (void) DIGI_FREE((void **) &pTemp);
    }

    if (NULL != pValue)
    {
        (void) DIGI_FREE((void **) &pValue);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS CERT_ENROLL_addCsrAttributeJSON(ubyte *pIn, ubyte4 inLen, CertCsrCtx *pCsrCtx)
{
    MSTATUS status = OK;
    nameAttr *pNameAttr[MAX_CSR_NAME_ATTRS] = {0};
    ubyte4 attrCnt = 0;
    DER_ITEMPTR pSanRoot = NULL;
    DER_ITEMPTR pExtKeyUsageRoot = NULL;
    ubyte2 keyUsage = 0;
    byteBoolean sanCritical = FALSE;
    byteBoolean extKeyUsageCritical = FALSE;
    byteBoolean keyUsageCritical = FALSE;
    TimeDate startDate = {0};
    TimeDate endDate = {0};
    JSON_ContextType *pJCtx = NULL;
    ubyte4 arrNdx;
    JSON_TokenType arrToken = { 0 }, token = { 0 };
    ubyte4 i;
    sbyte4 cmp = -1;
    sbyte *pId = NULL, *pValue = NULL;
    ubyte4 tempLen = 0;

    /* Internal method, NULL checks not necc */
    status = JSON_acquireContext( &pJCtx);
    if( OK != status)
        goto exit;

    status = JSON_parse(pJCtx, (const sbyte *)pIn, inLen, &tempLen);
    if( OK != status)
        goto exit;

    status = JSON_getJsonArrayValue(pJCtx, 0, "fields", &arrNdx, &arrToken, TRUE);
    if (OK != status)
        goto exit;

    arrNdx++;
    for (i = 0; i < arrToken.elemCnt; i++)
    {
        status = JSON_getToken(pJCtx, arrNdx, &token);
        if (OK != status)
            goto exit;

        if (JSON_Object != token.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        (void ) DIGI_FREE((void **) &pId);
        status = JSON_getJsonStringValue(pJCtx, arrNdx, "id", &pId, TRUE);
        if (OK != status)
            goto exit;

        if(0 == DIGI_STRCMP(pId, (sbyte *) "signature_algorithm"))
        {
            if (TRUE == pCsrCtx->processSigAlgs)
            {
                /* Lookup signing algorithm */
                status = CERT_ENROLL_getSignatureAlgorithm(pCsrCtx, pJCtx, arrNdx);
            }
            else
            {
                /* Caller has already set signing algorithm */
                status = OK;
            }
        }
        else if (DIGI_STRLEN(pId) > 4 &&
                 0 == DIGI_MEMCMP((ubyte *) pId, (ubyte *) "san.", 4, &cmp) &&
                 0 == cmp)
        {
            (void) DIGI_FREE((void **) &pValue);
            status = CERT_ENROLL_getJsonStringValueWithEval(pJCtx, arrNdx, pCsrCtx, &pValue);
            if (OK != status)
                goto exit;

            /* addCsrSANField will take ownership of the pValue pointer, so pass in reference */
            status = CERT_ENROLL_addCsrSANField(pCsrCtx, &pSanRoot, &sanCritical, pId, &pValue);
        }
        /* Other extensions all grouped together */
        else if (DIGI_STRLEN(pId) > 11 &&
                 0 == DIGI_MEMCMP((ubyte *) pId, (ubyte *) "extensions.", 11, &cmp) &&
                 0 == cmp)
        {
            (void) DIGI_FREE((void **) &pValue);
            status = CERT_ENROLL_getJsonStringValueWithEval(pJCtx, arrNdx, pCsrCtx, &pValue);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_addExtensionField(&pCsrCtx->reqAttr.pExtensions, pId, &pValue);
        }
        else if (DIGI_STRLEN(pId) > 10 &&
                 0 == DIGI_MEMCMP((ubyte *) pId, (ubyte *) "key_usage.", 10, &cmp) &&
                 0 == cmp)
        {
            (void) DIGI_FREE((void **) &pValue);
            status = CERT_ENROLL_getJsonStringValueWithEval(pJCtx, arrNdx, pCsrCtx, &pValue);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_addKeyUsageField(&keyUsage, &keyUsageCritical, pCsrCtx->keyType, pId, pValue);
        }
        else if (DIGI_STRLEN(pId) > 19 &&
                 0 == DIGI_MEMCMP((ubyte *) pId, (ubyte *) "extended_key_usage.", 19, &cmp) &&
                 0 == cmp)
        {
            (void) DIGI_FREE((void **) &pValue);
            status = CERT_ENROLL_getJsonStringValueWithEval(pJCtx, arrNdx, pCsrCtx, &pValue);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_addExtendedKeyUsageField(&pExtKeyUsageRoot, &extKeyUsageCritical, pId, pValue);
        }
        else if(0 == DIGI_STRCMP(pId, (sbyte *) "validity.from"))
        {
            (void) DIGI_FREE((void **) &pValue);
            status = CERT_ENROLL_getJsonStringValueWithEval(pJCtx, arrNdx, pCsrCtx, &pValue);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_addValidityDate(&startDate, pValue);
        }
        else if(0 == DIGI_STRCMP(pId, (sbyte *) "validity.to"))
        {
            (void) DIGI_FREE((void **) &pValue);
            status = CERT_ENROLL_getJsonStringValueWithEval(pJCtx, arrNdx, pCsrCtx, &pValue);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_addValidityDate(&endDate, pValue);
        }
        /* Other subject fields all grouped together */
        else
        {
            (void) DIGI_FREE((void **) &pValue);
            status = CERT_ENROLL_getJsonStringValueWithEval(pJCtx, arrNdx, pCsrCtx, &pValue);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_addCsrField(&pNameAttr[attrCnt], &attrCnt, pId, pValue);
        }
        if (OK != status)
            goto exit;

        status = JSON_getLastIndexInObject(pJCtx, arrNdx, &arrNdx);
        if (OK != status)
            goto exit;

        arrNdx++;
    }

    if (NULL == pCsrCtx->pKey && certEnrollAlgUndefined != pCsrCtx->keyAlgorithm)
    {
        (void) DIGI_FREE((void **) &pValue);
        status = CERT_ENROLL_keyAlgorithmToString(pCsrCtx->keyAlgorithm, &pValue);
        if (OK != status)
            goto exit;

        status = CERT_ENROLL_addCsrSANField(
            pCsrCtx, &pSanRoot, NULL, "san.directory_name.key_algorithm", &pValue);
        if (OK != status)
            goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    if (EXT_ENROLL_FLOW_TPM2_IAK == pCsrCtx->extFlow || EXT_ENROLL_FLOW_TPM2_IDEVID == pCsrCtx->extFlow)
    {
        status = CERT_ENROLL_addCsrSANField(
            pCsrCtx, &pSanRoot, NULL, "san.other_name.permanent_identifier", &pValue);
        if (OK != status)
            goto exit;

        status = CERT_ENROLL_addCsrSANField(
            pCsrCtx, &pSanRoot, NULL, "san.other_name.hardware_module_name", &pValue);
        if (OK != status)
            goto exit;
    }
#endif

    /* add the SAN */
    if (NULL != pSanRoot)
    {
        /* Re-use pId as the SAN serilization */
        (void) DIGI_FREE((void **) &pId);
        status = DER_Serialize(pSanRoot, (ubyte **) &pId, &tempLen);
        if (OK != status)
            goto exit;

        status = CERT_ENROLL_addOtherExt(&pCsrCtx->reqAttr.pExtensions, subjectAltName_OID, sanCritical, (ubyte **) &pId, tempLen);
        if (OK != status)
            goto exit;
    }

    /* add the keyUsage */
    if (0 != keyUsage)
    {
        /* make space for the extensions */
        if (NULL == pCsrCtx->reqAttr.pExtensions)
        {
            status = DIGI_CALLOC(
                (void **) &(pCsrCtx->reqAttr.pExtensions),
                sizeof(certExtensions), 1);
            if (OK != status)
                goto exit;
        }

        pCsrCtx->reqAttr.pExtensions->keyUsage = keyUsage;
        pCsrCtx->reqAttr.pExtensions->hasKeyUsage = TRUE;
     /* pCsrCtx->reqAttr.pExtensions->keyUsageCritical = keyUsageCritical */
    }

    /* add the extended key usage */
    if (NULL != pExtKeyUsageRoot)
    {
        /* Re-use pId as the SAN serilization */
        (void) DIGI_FREE((void **) &pId);
        status = DER_Serialize(pExtKeyUsageRoot, (ubyte **) &pId, &tempLen);
        if (OK != status)
            goto exit;

        status = CERT_ENROLL_addOtherExt(&pCsrCtx->reqAttr.pExtensions, id_ce_extKeyUsage_OID, extKeyUsageCritical, (ubyte **) &pId, tempLen);
        if (OK != status)
            goto exit;
    }

    status = JSON_getJsonArrayValue(pJCtx, 0, "extAttrs", &arrNdx, &arrToken, TRUE);
    if (OK == status && arrToken.elemCnt > 0)
    {
        arrNdx++;
        status = CERT_ENROLL_addExtAttrs(&pCsrCtx->reqAttr.pExtensions, pJCtx, arrNdx, &arrToken);
        if (OK != status)
            goto exit;
    }
    else if (ERR_NOT_FOUND == status)
    {
        status = OK;
    }
    else
    {
        goto exit;
    }

    status = CERT_ENROLL_createCertDistinguishedName(pNameAttr, attrCnt, &pCsrCtx->pCertSubjectInfo);
    if (OK != status)
        goto exit;

    status = CERT_ENROLL_setCertDates(pCsrCtx->pCertSubjectInfo, &startDate, &endDate);

exit:

    if (NULL != pSanRoot)
    {
        (void) TREE_DeleteTreeItem((TreeItem *) pSanRoot);
        pSanRoot = NULL;
    }

    if (NULL != pExtKeyUsageRoot)
    {
        (void) TREE_DeleteTreeItem((TreeItem *) pExtKeyUsageRoot);
        pExtKeyUsageRoot = NULL;
    }

    if (NULL != pJCtx)
    {
        (void) JSON_releaseContext(&pJCtx);
    }

    (void) DIGI_FREE((void **) &pValue);
    (void) DIGI_FREE((void **) &pId);

    return status;
}


/*-------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__)
byteBoolean CERT_ENROLL_isTCGPolicy(
    ubyte **ppPolicyOids)
{
    if (NULL != ppPolicyOids)
    {
        while (NULL != *ppPolicyOids)
        {
            if ( (tcg_cap_verifiedTPMFixed_OID == *ppPolicyOids) ||
                (tcg_cap_verifiedTPMRestricted_OID == *ppPolicyOids) )
            {
                return TRUE;
            }

            ppPolicyOids++;
        }
    }

    return FALSE;
}
#endif

/*-------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__)

static ubyte *ppTpm2IDevIDCertPolicies[] = {
    (ubyte *) tcg_cap_verifiedTPMResidency_OID,
    (ubyte *) tcg_cap_verifiedTPMFixed_OID,
    NULL
};

static ubyte *ppTpm2IAKCertPolicies[] = {
    (ubyte *) tcg_cap_verifiedTPMResidency_OID,
    (ubyte *) tcg_cap_verifiedTPMRestricted_OID,
    NULL
};

#endif

/*-------------------------------------------------------------------------*/

static ubyte4 CERT_ENROLL_keyAlgorithmToKeyType(
    CertEnrollAlg keyAlgo)
{
    switch (keyAlgo)
    {
        case rsa2048:
        case rsa3072:
        case rsa4096:
            return akt_rsa;
        case ecdsaP256:
        case ecdsaP384:
        case ecdsaP521:
            return akt_ecc;
        case eddsaEd25519:
        case eddsaEd448:
            return akt_ecc_ed;
        case mldsa44:
        case mldsa65:
        case mldsa87:
        case fndsa1024:
        case slhdsaSha128f:
        case slhdsaSha128s:
        case slhdsaSha192f:
        case slhdsaSha192s:
        case slhdsaSha256f:
        case slhdsaSha256s:
        case slhdsaShake128f:
        case slhdsaShake128s:
        case slhdsaShake192f:
        case slhdsaShake192s:
        case slhdsaShake256f:
        case slhdsaShake256s:
            return akt_qs;
        default:
            return akt_undefined;
    }
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_addCsrAttributes(
    CertCsrCtx *pCsrCtx,
    CsrFormat format,
    CertEnrollMode cmcType,
    EvalFunction evalFunction,
    void *pEvalFunctionArg,
    AsymmetricKey *pKey,
    CertEnrollAlg keyAlgorithm,
    byteBoolean processSigAlgs,
    ubyte4 hashId,
    ubyte *pIn,
    ubyte4 inLen,
    CertExtCtx *pExtCtx,
    ExtendedEnrollFlow extFlow
)
{
    MSTATUS status = ERR_NULL_POINTER;
    MOC_UNUSED(cmcType); /* cmcType needed? */
    MOC_UNUSED(pExtCtx);
#if defined(__ENABLE_DIGICERT_TAP__)
    ubyte **ppCertPolicyOids = NULL;
#endif

    if (NULL == pCsrCtx || NULL == pIn)
        goto exit;

    /* set the keyType for later hashAlgo validation */
    if (NULL != pKey)
    {
        pCsrCtx->keyType = pKey->type;
    }
    else
    {
        pCsrCtx->keyType = CERT_ENROLL_keyAlgorithmToKeyType(keyAlgorithm);
    }
    pCsrCtx->pKey = pKey;
    pCsrCtx->keyAlgorithm = keyAlgorithm;
    pCsrCtx->processSigAlgs = processSigAlgs;
    pCsrCtx->hashId = hashId;

    /* set the eval function for later use */
    if (NULL != evalFunction)
    {
        pCsrCtx->evalFunction = evalFunction;
        pCsrCtx->pEvalFunctionArg = pEvalFunctionArg;
    }
    else
    {
        pCsrCtx->evalFunction = NULL;
        pCsrCtx->pEvalFunctionArg = NULL;
    }

    pCsrCtx->extFlow = extFlow;

    if (JSON == format)
    {
        status = CERT_ENROLL_addCsrAttributeJSON(pIn, inLen, pCsrCtx);
    }
    /* TODO how to set signAlgo (hashId) in TOML or JSONAlt cases */
    else if (TOML == format)
    {
        status = CERT_ENROLL_addCsrAttributeTOML(pIn, inLen, pCsrCtx, &pCsrCtx->pCertSubjectInfo, &pCsrCtx->reqAttr.pExtensions);
    }
#ifdef __ENABLE_CERT_ENROLL_ALT_FORMATS__
    else if (JSON_ALT == format)
    {
        status = CERT_ENROLL_addCsrAttributeJSONAlt(pIn, inLen, &pCsrCtx->pCertSubjectInfo, &pCsrCtx->reqAttr);
    }
#endif
    else
    {
        status = ERR_INVALID_INPUT;
    }
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    if (EXT_ENROLL_FLOW_TPM2_IAK == pCsrCtx->extFlow)
    {
        ppCertPolicyOids = ppTpm2IAKCertPolicies;
    }
    else if (EXT_ENROLL_FLOW_TPM2_IDEVID == pCsrCtx->extFlow)
    {
        ppCertPolicyOids = ppTpm2IDevIDCertPolicies;
    }

    if (NULL != ppCertPolicyOids)
    {
        status = CERT_ENROLL_setCertificatePolicy(
            &pCsrCtx->reqAttr.pExtensions, ppCertPolicyOids);
    }
#endif

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_cleanupCsrCtx(
    CertCsrCtx *pCsrCtx
)
{
    MSTATUS status = OK, fstatus = OK;

    if (NULL == pCsrCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pCsrCtx->reqAttr.pChallengePwd)
    {
        status = DIGI_MEMSET_FREE((ubyte **) &pCsrCtx->reqAttr.pChallengePwd, pCsrCtx->reqAttr.challengePwdLength);
    }

    if (NULL != pCsrCtx->reqAttr.pExtensions)
    {
        CERT_ENROLL_freeExtensions(pCsrCtx->reqAttr.pExtensions);
        fstatus = DIGI_MEMSET_FREE((ubyte **) &pCsrCtx->reqAttr.pExtensions, sizeof(certExtensions));
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pCsrCtx->reqAttr.pOtherAttrs)
    {
        ubyte4 i = 0;
        for (; i < pCsrCtx->reqAttr.otherAttrCount; i++)
        {
            if (NULL != pCsrCtx->reqAttr.pOtherAttrs[i].oid)
            {
                fstatus = DIGI_FREE((void **) &pCsrCtx->reqAttr.pOtherAttrs[i].oid);
                if (OK == status)
                    status = fstatus;
            }

            if (NULL != pCsrCtx->reqAttr.pOtherAttrs[i].pValue)
            {
                fstatus = DIGI_MEMSET_FREE(&pCsrCtx->reqAttr.pOtherAttrs[i].pValue, pCsrCtx->reqAttr.pOtherAttrs[i].valueLen);
                if (OK == status)
                    status = fstatus;
            }
        }

        fstatus = DIGI_FREE((void **) &pCsrCtx->reqAttr.pOtherAttrs);
        if (OK == status)
            status = fstatus;

        pCsrCtx->reqAttr.otherAttrCount = 0;
    }

    fstatus = CA_MGMT_freeCertDistinguishedName(&pCsrCtx->pCertSubjectInfo);
    if (OK == status)
        status = fstatus;

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static
MSTATUS CERT_ENROLL_addIssuerAndSerialNumber(DER_ITEMPTR pParent, CStream cs, ASN1_ITEMPTR pIssuer,
                                             ASN1_ITEMPTR pSerialNumber, DER_ITEMPTR *ppIssuerAndSerialNumber)
{
    MSTATUS status;
    DER_ITEMPTR pIssuerAndSerialNumber;

    if (OK > (status = DER_AddSequence(pParent, &pIssuerAndSerialNumber)))
        goto exit;

    if ( OK > (status = DER_AddASN1Item( pIssuerAndSerialNumber, pIssuer, cs, NULL)))
        goto exit;

    if ( OK > (status = DER_AddASN1Item( pIssuerAndSerialNumber, pSerialNumber, cs, NULL)))
        goto exit;

    if (ppIssuerAndSerialNumber)
    {
        *ppIssuerAndSerialNumber = pIssuerAndSerialNumber;
    }

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

static MSTATUS
CERT_ENROLL_generateOIDFromString(const sbyte* oidStr, ubyte** oid)
{
    MSTATUS status = OK;
    byteBoolean w;

    status = BEREncodeOID(oidStr, &w, oid);
    if (OK != status)
        goto exit;

    *oid = *oid + 1;				/* Do not include the type field of the oid encoded array.*/

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_addReqAttribute(
    CertCsrCtx *pCsrCtx,
    ReqAttrType type,
    ubyte *pValue,
    ubyte4 valueLen
)
{
    MSTATUS status = ERR_NULL_POINTER;
    requestAttributesEx *pReqAttr = NULL;
    ubyte *pOid = NULL;

    sbyte *pAlgId = NULL;
    ubyte *pOidFromAlgId = NULL;
    DER_ITEMPTR pItemPtr = NULL;
    DER_ITEMPTR pTemp = NULL;
    ubyte *pSerializedDer = NULL;
    ubyte4 serializedDerLen = 0;

    CStream certStream = {0};
    MemFile memFile;
    ASN1_ITEMPTR pIssuer = NULL;
    ASN1_ITEMPTR pSerialNumber = NULL;
    ASN1_ITEMPTR pSelfCertificate = NULL;

    byteBoolean addOtherAttr = TRUE;

    static const ubyte smimeCapabilitiesOid[] = {9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0F};
    /* id-aa-decryptKeyID 1.2.840.113549.1.9.16.2.37 */
    static const ubyte decryptKeyIdentifider_OID[]     = {0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x25};
    /* id-aa-asymmDecryptKeyID 1.2.840.113549.1.9.16.2.54 */
    static const ubyte asymDecryptKeyIdentifider_OID[] = {0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x36};
    static const ubyte renewalCertOid[] = {9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0D, 0x01};

    if (NULL == pCsrCtx || (NULL == pValue && valueLen) )
        goto exit;

    pReqAttr = &(pCsrCtx->reqAttr);

    /* Are we out of space? */
    if (pReqAttr->otherAttrCount >= MAX_REQ_ATTRS)
    {
        status = ERR_CERT_ENROLL_REQ_ATTRIBUTE_OVERFLOW;
        goto exit;
    }

    /* first time we allocate enough space for all possibilities */
    if (NULL == pReqAttr->pOtherAttrs)
    {
        status = DIGI_CALLOC((void**)&(pReqAttr->pOtherAttrs), sizeof(MocRequestAttr), MAX_REQ_ATTRS);
        if (OK != status)
            goto exit;

        pReqAttr->otherAttrCount = 0;
    }

    switch (type)
    {
        case smimeCapabilities:

            status = DIGI_MALLOC((void**) &pOid, sizeof(smimeCapabilitiesOid));
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pOid, smimeCapabilitiesOid, sizeof(smimeCapabilitiesOid));
            if (OK != status)
                goto exit;

            /* pValue is the encryption alg id, convert to a string (sbyte *) */
            status = DIGI_MALLOC((void**) &pAlgId, valueLen+1);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY((ubyte *) pAlgId, pValue, valueLen);
            if (OK != status)
                goto exit;

            pAlgId[valueLen] = (sbyte) '\0';

            /* following API sets pOidFromAlgId to one byte after the memory allocation */
            status = CERT_ENROLL_generateOIDFromString(pAlgId, &pOidFromAlgId);
            if (OK != status)
                goto exit;

            status = DER_AddSequence (NULL, &pItemPtr);
            if (OK != status)
                goto exit;

            status = DER_AddSequence( pItemPtr, &pTemp);
            if (OK != status)
                goto exit;

            status = DER_AddOID (pTemp, pOidFromAlgId, NULL);
            if (OK != status)
                goto exit;

            status = DER_Serialize(pItemPtr, &pSerializedDer, &serializedDerLen);
            if (OK != status)
                goto exit;

            break;

        case decryptKeyIdentifier:

            status = DIGI_MALLOC((void**) &pOid, sizeof(decryptKeyIdentifider_OID));
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pOid, decryptKeyIdentifider_OID, sizeof(decryptKeyIdentifider_OID));
            if (OK != status)
                goto exit;

            /* pValue is a key alias */
            status = DER_AddItem(NULL, OCTETSTRING, valueLen, pValue, &pItemPtr);
            if (OK != status)
                goto exit;

            status = DER_Serialize(pItemPtr, &pSerializedDer, &serializedDerLen);
            if (OK != status)
                goto exit;

            break;

        case asymDecryptKeyIdentifier:

            status = DIGI_MALLOC((void**) &pOid, sizeof(asymDecryptKeyIdentifider_OID));
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pOid, asymDecryptKeyIdentifider_OID, sizeof(asymDecryptKeyIdentifider_OID));
            if (OK != status)
                goto exit;

            /* pValue is the asym smime certificate */
            MF_attach(&memFile, valueLen, pValue);
            CS_AttachMemFile(&certStream, &memFile );

            status = X509_parseCertificate(certStream, &pSelfCertificate);
            if (OK != status)
                goto exit;

            /* get issuer and serial number of certificate */
            status = X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pSelfCertificate), &pIssuer, &pSerialNumber);
            if (OK != status)
                goto exit;

            status = CERT_ENROLL_addIssuerAndSerialNumber(NULL, certStream, pIssuer, pSerialNumber, &pItemPtr);
            if (OK != status)
                goto exit;

            status = DER_Serialize(pItemPtr, &pSerializedDer, &serializedDerLen);
            if (OK != status)
                goto exit;

            break;

        case renewalCert:

            status = DIGI_MALLOC((void**) &pOid, sizeof(renewalCertOid));
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pOid, renewalCertOid, sizeof(renewalCertOid));
            if (OK != status)
                goto exit;

            /* pValue is the certificate, just copy over, already der form */
            status = DIGI_MALLOC((void **) &pSerializedDer, valueLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSerializedDer, pValue, valueLen);
            if (OK != status)
                goto exit;

            break;

        /* case addSubjectKeyIdentifierExtension? needs an AsymKey */

        case challengePassword:

            status = DIGI_MALLOC((void**) &pReqAttr->pChallengePwd, valueLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY( (ubyte *) pReqAttr->pChallengePwd, pValue, valueLen);
            if (OK != status)
                goto exit;

            pReqAttr->challengePwdLength = valueLen;
            addOtherAttr = FALSE;
            break;

        default:
            status = ERR_INVALID_ARG;
            goto exit;

    }

    if (addOtherAttr)
    {
        pReqAttr->pOtherAttrs[pReqAttr->otherAttrCount].oid = pOid; pOid = NULL;
        pReqAttr->pOtherAttrs[pReqAttr->otherAttrCount].pValue = pSerializedDer; pSerializedDer = NULL;
        pReqAttr->pOtherAttrs[pReqAttr->otherAttrCount].valueLen = serializedDerLen;
        pReqAttr->otherAttrCount++;
    }

exit:

    if (NULL != pOid)
    {
        (void) DIGI_FREE((void **) &pOid);
    }

    if (NULL != pAlgId)
    {
        (void) DIGI_FREE((void **) &pAlgId);
    }

    /* original memory allocation for pOidFromAlgId was one byte less.
       Non-null always indicate a true memory address so no need to check if == 1 */
    if (NULL != pOidFromAlgId)
    {
        ubyte *pOidFromAlgIdOrig = pOidFromAlgId - 1;
        (void) DIGI_FREE((void **) &pOidFromAlgIdOrig);
    }

    if (NULL != pSerializedDer)
    {
        (void) DIGI_MEMSET_FREE(&pSerializedDer, serializedDerLen);
    }

    if (NULL != pItemPtr)
    {
        (void) TREE_DeleteTreeItem ((TreeItem *)pItemPtr);
    }

    if (NULL != pTemp)
    {
        (void) TREE_DeleteTreeItem ((TreeItem *)pTemp);
    }

    if (NULL != pSelfCertificate)
    {
        (void) TREE_DeleteTreeItem ((TreeItem *)pSelfCertificate);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_generateCMCRequest(
    CertKeyCtx *pKeyCtx,
    void *pTapKeyCtx,
    CertCsrCtx *pCsrCtx,
    CertExtCMCCtx *pExtCMCCtx,
    CertSignAttrCtx *pSignAttrCtx,
    CertEnrollMode cmcType,
    ubyte **ppCMC,
    ubyte4 *pCMCLen
);

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_generateCSRRequest(
    CertKeyCtx *pKeyCtx,
    void *pTapKeyCtx,
    CertCsrCtx *pCsrCtx,
    CertEnrollMode cmcType,
    ubyte **ppCsr,
    ubyte4 *pCsrLen
)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pOutReq = NULL;
    ubyte4 reqLen = 0;

    MOC_UNUSED(cmcType);
    MOC_UNUSED(pTapKeyCtx); /* TODO do we validate this goes with the pKeyCtx->pKey? That was deserialized */

    if (NULL == pKeyCtx || NULL == pCsrCtx || NULL == ppCsr || NULL == pCsrLen)
        goto exit;

    status = PKCS10_GenerateCertReqFromDNEx2(pKeyCtx->pKey, pCsrCtx->hashId,
                                            pCsrCtx->pCertSubjectInfo, &pCsrCtx->reqAttr, &pOutReq, &reqLen);
    if (OK != status)
        goto exit;

    status = PKCS10_CertReqToCSR(pOutReq, reqLen, ppCsr, pCsrLen);
    if (OK != status)
        goto exit;

exit:

    if (pOutReq)
    {
        (void) DIGI_FREE((void **)&pOutReq);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_ENROLL_parseResponse(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pInput,
    ubyte4 inputLen,
    AsymmetricKey *pPrivKey,
    intBoolean chainOnly,
    certDescriptor **ppCertDescArray,
    ubyte4 *pCertDescArrayLen
)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pDecoded = NULL;
    ubyte4 decodedLen = 0;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot = NULL, pChild;
    ubyte4 numCerts = 0;
    certDescriptor *pCertDescArray = NULL;
    ubyte4 i = 0;
    CERTS_DATA *pCertData = NULL;
    intBoolean isAlreadyDecoded = FALSE;

    if (NULL == pInput || NULL == ppCertDescArray || NULL == pCertDescArrayLen)
        goto exit;

    status = CA_MGMT_decodeCertificate(pInput, inputLen, &pDecoded, &decodedLen);
    if (OK != status)
    {
        /* If base64 decode fails, assume input is already binary/decoded */
        pDecoded = pInput;
        decodedLen = inputLen;
        isAlreadyDecoded = TRUE;
        status = OK;
    }

    MF_attach(&mf, decodedLen, pDecoded);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
        goto exit;

    status = PKCS7_GetCertificates(pRoot, cs, &pChild);
    if (OK != status)
        goto exit;

    status = PKCS7_filterCertificates( MOC_ASYM(hwAccelCtx) pChild, cs, pPrivKey, chainOnly,
                                       &pCertData, &numCerts);
    if (OK != status)
        goto exit;

    if (numCerts > 0)
    {
        status = DIGI_CALLOC((void **) &pCertDescArray, numCerts, sizeof(certDescriptor));
        if (OK != status)
            goto exit;

        for (i = 0; i < numCerts; i++)
        {
            status = DIGI_MALLOC_MEMCPY((void **) &pCertDescArray[i].pCertificate, pCertData[i].certDataLen,
                                       (void *) pCertData[i].pCertData, pCertData[i].certDataLen);
            if (OK != status)
                goto exit;

            pCertDescArray[i].certLength = pCertData[i].certDataLen;
        }
    }

    *ppCertDescArray = pCertDescArray; pCertDescArray = NULL;
    *pCertDescArrayLen = numCerts;

exit:

    if (NULL != pCertData)
    {
        /* underneath pointers weren't allocated, just positioned within the asn1 */
        (void) DIGI_MEMSET_FREE((ubyte **) &pCertData, numCerts * sizeof(CERTS_DATA));
    }

    if (NULL != pCertDescArray)
    {
        for (i = 0; i < numCerts; i++)
        {
            (void) CA_MGMT_freeCertificate(&pCertDescArray[i]);
        }

        (void) DIGI_FREE((void **) &pCertDescArray);
    }

    if (NULL != pRoot)
    {
        (void) TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    if (NULL != pDecoded && !isAlreadyDecoded)
    {
        (void) DIGI_MEMSET_FREE(&pDecoded, decodedLen);
    }

    return status;
}

/*-------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__)

static MSTATUS CERT_ENROLL_utilReadId(sbyte *pStr, TAP_Buffer *pOutId)
{
    MSTATUS status = ERR_INVALID_ARG;
    ubyte *pId = NULL;
    ubyte4 idLen = 0;
    intBoolean isIdHex = FALSE;

    idLen = (ubyte4) DIGI_STRLEN(pStr);
    if ( (idLen >= 2) && pStr[0] == '0' && (pStr[1] == 'x' || pStr[1] == 'X') )
        isIdHex = TRUE;

    /* internal method, NULL checks not necc */
    if (isIdHex)
    {
       /* use idLen as a temp for string form lem */
        if (idLen < 4 || idLen & 0x01)
        {
            goto exit;
        }

        /* now get the real id Len */
        idLen = (idLen - 2) / 2;

        status = DIGI_MALLOC((void **) &pId, idLen);
        if (OK != status)
            goto exit;

        status = DIGI_ATOH(pStr + 2, idLen*2, pId);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_MALLOC((void **) &pId, idLen + 1); /* we'll add a zero byte for string form printing */
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pId, (ubyte *) pStr, idLen);
        if (OK != status)
            goto exit;

        pId[idLen] = 0x0;
    }

    pOutId->pBuffer = pId; pId = NULL;
    pOutId->bufferLen = idLen; idLen = 0;

exit:

    if (NULL != pId)
    {
        (void) DIGI_MEMSET_FREE(&pId, idLen);
    }

    return status;
}

static MSTATUS CERT_ENROLL_utilStrToInt(sbyte *pStr, ubyte8 *pInt)
{
    MSTATUS status;
    ubyte4 strLen, tmpLen, i;
    ubyte pHex[8] = {0};
    sbyte4 intVal = 0;
    sbyte *pMaxInt = (sbyte *) "2147483647";
    sbyte *pStop = NULL;

    if ( (NULL == pStr) || (NULL == pInt) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    strLen = DIGI_STRLEN(pStr);
    if (0 == strLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    tmpLen = DIGI_STRLEN((sbyte *)"0x");
    if ( (strLen >= tmpLen) &&
         (0 == DIGI_STRNICMP(pStr,(sbyte *)"0x", tmpLen)) )
    {
        strLen -= tmpLen;
        pStr += tmpLen;
        if (strLen > 16)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        tmpLen = (16 - strLen) >> 1;
        status = DIGI_convertHexString(
            (char *) pStr, pHex + tmpLen, sizeof(pHex) - tmpLen);
        if (OK != status)
        {
            goto exit;
        }

        U8INIT_HI(*pInt, DIGI_NTOHL(pHex));
        U8INIT_LO(*pInt, DIGI_NTOHL(pHex + 4));
    }
    else
    {
        tmpLen = DIGI_STRLEN(pMaxInt);
        if ( (strLen > tmpLen) || (FALSE == DIGI_ISDIGIT(pStr[0])) )
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        /* Check for overflow */
        if (strLen == tmpLen)
        {
            for (i = 0; i < tmpLen; i++)
            {
                if (FALSE == DIGI_ISDIGIT(pStr[i]))
                {
                    status = ERR_INVALID_INPUT;
                    goto exit;
                }

                if (pStr[i] > pMaxInt[i])
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }
                else if (pStr[i] < pMaxInt[i])
                {
                    break;
                }
            }
        }

        intVal = DIGI_ATOL(pStr, (const sbyte **) &pStop);
        if (*pStop != '\0')
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        U8INIT_HI(*pInt, 0);
        U8INIT_LO(*pInt, intVal);
        status = OK;
    }

exit:

    return status;
}

extern MSTATUS CERT_ENROLL_parseTAPAttributes(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    CertEnrollAlg alg,
    CertEnrollTAPAttributes *pAttributes)
{
    MSTATUS status;
    ubyte4 i;
    ubyte4 attrNdx, arrNdx, objNdx;
    JSON_TokenType arrtoken = { 0 };
    JSON_TokenType token = { 0 };
    sbyte *pHandle = NULL;
    sbyte4 moduleId;
    intBoolean primary;
    sbyte *pHierarchy = NULL;
    sbyte *pKeyUsage = NULL;
    sbyte *pSigScheme = NULL;
    sbyte *pEncScheme = NULL;

    if ( (NULL == pJCtx) || (NULL == pAttributes) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_getObjectIndex(
        pJCtx, "secureModuleKeyAttributes", ndx, &attrNdx, TRUE);
    if (ERR_NOT_FOUND == status)
    {
        status = OK;
        goto exit;
    }
    if (OK != status)
    {
        goto exit;
    }

    attrNdx++;

    status = JSON_getJsonIntegerValue(
        pJCtx, attrNdx, "secureModuleId", &moduleId, TRUE);
    if (OK == status)
    {
        pAttributes->moduleId = (ubyte4) moduleId;
    }
    else if (ERR_NOT_FOUND != status)
    {
        goto exit;
    }
    else
    {
        status = OK;
    }

    status = JSON_getJsonBooleanValue(
        pJCtx, attrNdx, "primary", &primary, TRUE);
    if (OK == status)
    {
        pAttributes->primary = primary;
    }
    else if (ERR_NOT_FOUND != status)
    {
        goto exit;
    }
    else
    {
        status = OK;
    }

    status = JSON_getJsonStringValue(
        pJCtx, attrNdx, "keyTokenHierarchy", &pHierarchy, TRUE);
    if (OK == status)
    {
        if (0 == DIGI_STRCMP(pHierarchy, "STORAGE"))
        {
            pAttributes->hierarchy = TAP_HIERARCHY_STORAGE;
        }
        else if (0 == DIGI_STRCMP(pHierarchy, "ENDORSEMENT"))
        {
            pAttributes->hierarchy = TAP_HIERARCHY_ENDORSEMENT;
        }
        else if (0 == DIGI_STRCMP(pHierarchy, "PLATFORM"))
        {
            pAttributes->hierarchy = TAP_HIERARCHY_PLATFORM;
        }
    }
    else if (ERR_NOT_FOUND != status)
    {
        goto exit;
    }
    else
    {
        status = OK;
    }

    status = JSON_getJsonStringValue(
        pJCtx, attrNdx, "keyUsage", &pKeyUsage, TRUE);
    if (OK == status)
    {
        if (0 == DIGI_STRCMP(pKeyUsage, "SIGNING"))
        {
            pAttributes->keyUsage = TAP_KEY_USAGE_SIGNING;
        }
        else if (0 == DIGI_STRCMP(pKeyUsage, "DECRYPT"))
        {
            pAttributes->keyUsage = TAP_KEY_USAGE_DECRYPT;
        }
        else if (0 == DIGI_STRCMP(pKeyUsage, "GENERAL"))
        {
            pAttributes->keyUsage = TAP_KEY_USAGE_GENERAL;
        }
        else if (0 == DIGI_STRCMP(pKeyUsage, "ATTEST"))
        {
            pAttributes->keyUsage = TAP_KEY_USAGE_ATTESTATION;
        }
    }
    else if (ERR_NOT_FOUND != status)
    {
        goto exit;
    }
    else
    {
        status = OK;
    }

    status = JSON_getJsonStringValue(
        pJCtx, attrNdx, "sigScheme", &pSigScheme, TRUE);
    if (OK == status)
    {
            if ( (rsa2048 == alg) || (rsa3072 == alg) || (rsa4096 == alg) )
            {
                if (0 == DIGI_STRCMP(pSigScheme, "NONE"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_NONE;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "PKCS1_5"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "PSS_SHA1"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_PSS_SHA1;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "PSS_SHA256"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_PSS_SHA256;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "PKCS1_5_SHA1"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "PKCS1_5_SHA256"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "PKCS1_5_DER"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_PKCS1_5_DER;
                }
            }
            else if ( (ecdsaP256 == alg) || (ecdsaP384 == alg) || (ecdsaP521 == alg) )
            {
                if (0 == DIGI_STRCMP(pSigScheme, "NONE"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_NONE;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "ECDSA_SHA1"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "ECDSA_SHA224"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "ECDSA_SHA256"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "ECDSA_SHA384"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                }
                else if (0 == DIGI_STRCMP(pSigScheme, "ECDSA_SHA512"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                }
            }
            else
            {
                if (0 == DIGI_STRCMP(pSigScheme, "NONE"))
                {
                    pAttributes->sigScheme = TAP_SIG_SCHEME_NONE;
                }
            }
    }
    else if (ERR_NOT_FOUND != status)
    {
        goto exit;
    }
    else
    {
        status = OK;
    }

    status = JSON_getJsonStringValue(
        pJCtx, attrNdx, "encScheme", &pEncScheme, TRUE);
    if (OK == status)
    {
            if ( (rsa2048 == alg) || (rsa3072 == alg) || (rsa4096 == alg) )
            {
                if (0 == DIGI_STRCMP(pEncScheme, "NONE"))
                {
                    pAttributes->encScheme = TAP_ENC_SCHEME_NONE;
                }
                else if (0 == DIGI_STRCMP(pEncScheme, "PKCS1_5"))
                {
                    pAttributes->encScheme = TAP_ENC_SCHEME_PKCS1_5;
                }
                else if (0 == DIGI_STRCMP(pEncScheme, "PSS_SHA1"))
                {
                    pAttributes->encScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                }
                else if (0 == DIGI_STRCMP(pEncScheme, "PSS_SHA256"))
                {
                    pAttributes->encScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                }
            }
            else if ( (ecdsaP256 == alg) || (ecdsaP384 == alg) || (ecdsaP521 == alg) )
            {
                if (0 == DIGI_STRCMP(pEncScheme, "NONE"))
                {
                    pAttributes->encScheme = TAP_ENC_SCHEME_NONE;
                }
            }
            else
            {
                if (0 == DIGI_STRCMP(pEncScheme, "NONE"))
                {
                    pAttributes->encScheme = TAP_ENC_SCHEME_NONE;
                }
            }
    }
    else if (ERR_NOT_FOUND != status)
    {
        goto exit;
    }
    else
    {
        status = OK;
    }

    status = JSON_getJsonObjectIndex(pJCtx, ndx, "handles", &objNdx, TRUE);
    if (OK == status)
    {
        status = JSON_getJsonStringValue(
            pJCtx, objNdx, "key", &pHandle, TRUE);
        if (OK == status)
        {
            status = DIGI_CALLOC((void **) &pAttributes->pKeyHandle, 1, sizeof(TAP_Buffer));
            if (OK != status)
            {
                goto exit;
            }

            status = CERT_ENROLL_utilReadId(pHandle, pAttributes->pKeyHandle);
            if (OK != status)
            {
                goto exit;
            }
        }
        else if (ERR_NOT_FOUND != status)
        {
            goto exit;
        }
        else
        {
            status = OK;
        }

         DIGI_FREE((void **) &pHandle);
        status = JSON_getJsonStringValue(
            pJCtx, objNdx, "keyNonceNVHandle", &pHandle, TRUE);
        if (OK == status)
        {
            status = CERT_ENROLL_utilStrToInt(pHandle, &pAttributes->keyNonceHandle);
            if (OK != status)
            {
                goto exit;
            }
        }
        else if (ERR_NOT_FOUND != status)
        {
            goto exit;
        }
        else
        {
            status = OK;
        }

        DIGI_FREE((void **) &pHandle);
        status = JSON_getJsonStringValue(
            pJCtx, objNdx, "certificateNVHandle", &pHandle, TRUE);
        if (OK == status)
        {
            status = CERT_ENROLL_utilStrToInt(pHandle, &pAttributes->certHandle);
            if (OK != status)
            {
                goto exit;
            }
        }
        else if (ERR_NOT_FOUND != status)
        {
            goto exit;
        }
        else
        {
            status = OK;
        }
    }
    else if (ERR_NOT_FOUND != status)
    {
        goto exit;
    }
    else
    {
        status = OK;
    }

exit:

    DIGI_FREE((void **) &pHierarchy);
    DIGI_FREE((void **) &pKeyUsage);
    DIGI_FREE((void **) &pSigScheme);
    DIGI_FREE((void **) &pEncScheme);
    DIGI_FREE((void **) &pHandle);

    return status;
}

#endif /* __ENABLE_DIGICERT_TAP__ */