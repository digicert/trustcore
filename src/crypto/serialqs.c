/*
 * serialqs.c
 *
 * Serialize QS keys.
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

#if defined(__ENABLE_DIGICERT_PQC__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/mstdlib.h"
#include "../common/base64.h"

#include "../crypto/mocasym.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../crypto/keyblob.h"

#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/mocasn1.h"

#include "../crypto_interface/crypto_interface_qs.h"

static byteBoolean gOqsCompatibleFormat = FALSE;

/* WARNING: this API is not thread-safe */
extern void SERIALQS_setOqsCompatibleFormat(byteBoolean format)
{
    gOqsCompatibleFormat = format;
}

static MSTATUS DerEncodeQsPrivateKeyAlloc(QS_CTX *pCtx, ubyte **ppEncoding, ubyte4 *pEncodingLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte version = 0; /* version 0, rfc 5208 */
    ubyte *pDer = NULL;
    ubyte4 derLen = 0;
        
    ubyte *pQSBuffer = NULL;
    ubyte *pQSPtr = NULL;
    ubyte4 qsBufLen = 0;
    ubyte4 qsPrivLen = 0;
    ubyte4 qsPubLen = 0;
    ubyte *pKeyVal = NULL;
    ubyte4 lenLen = 0;
    ubyte4 qsKeyLen = 0;
    ubyte oid[MAX_PQC_OID_LEN] = {0};
    ubyte4 qsAlgId = 0;

    MAsn1Element *pArray = NULL;

    MAsn1TypeAndCount pTemplate[5] =
    {
        { MASN1_TYPE_SEQUENCE, 3 },
        { MASN1_TYPE_INTEGER, 0 },  /* version */
        { MASN1_TYPE_SEQUENCE, 1 }, /* AlgorithmIdentifier */
        { MASN1_TYPE_OID, 0 }, 
        { MASN1_TYPE_OCTET_STRING, 0 }, /* private key */
      /*  { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | 1, 0 } TODO optional attributes */
    };
    
    if (NULL == ppEncoding || NULL == pEncodingLen) /* other input params already checked */
        goto exit;
        
    /* get the oid for the qs alg in question first */
    status = CRYPTO_INTERFACE_QS_getAlg(pCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    /* get pure QS OID */
    status = CRYPTO_getQsAlgoOID(qsAlgId, oid);
    if (OK != status)
        goto exit;
    
    /* get the QS parameters, serialize the secret key so we have access to both the private (secret) and public keys */
    status = CRYPTO_INTERFACE_QS_serializeKeyAlloc(pCtx, MOC_ASYM_KEY_TYPE_PRIVATE, &pQSBuffer, &qsBufLen);
	if (OK != status)
		goto exit;

    /* we check the validity of the qsBuffer as we go */
    status = ERR_INTERNAL_ERROR;
    if (qsBufLen < 8)
        goto exit;

    /* public key is first! get length of it and private key before copying */
    pQSPtr = pQSBuffer;
    
    qsPubLen = (pQSPtr[0] << 24) | (pQSPtr[1] << 16) | (pQSPtr[2] << 8) | pQSPtr[3];
    pQSPtr += 4;

    if (qsBufLen < 8 + qsPubLen)
        goto exit;

    pQSPtr += qsPubLen;

    qsPrivLen = (pQSPtr[0] << 24) | (pQSPtr[1] << 16) | (pQSPtr[2] << 8) | pQSPtr[3];

    if (8 + qsPubLen + qsPrivLen > qsBufLen)
        goto exit;

    pQSPtr += 4;

    if (gOqsCompatibleFormat)
    {
        qsKeyLen = qsPrivLen + qsPubLen;

        /* The asn1 length is 1 byte if < 128 but multiple bytes if otherwise */
        if (qsKeyLen < 128)
            lenLen = 1;
        else if (qsKeyLen < 256)
            lenLen = 2;
        else if (qsKeyLen < 0x10000)
            lenLen = 3;
        else  /* assume we need at most 4 bytes for the asn1 length form */
            lenLen = 4;

        /* allocate space for the qs private key, octet string, and length bytes */
        status = DIGI_MALLOC ((void **) &pKeyVal, 1 + lenLen + qsKeyLen);
        if (OK != status)
            goto exit;

        pKeyVal[0] = OCTETSTRING;
        if (1 == lenLen)
        {
            pKeyVal[1] = (ubyte) qsKeyLen;
        }
        else
        {
            pKeyVal[1] = 0x80 | ((ubyte) (lenLen - 1));
            
            if (2 == lenLen)
            {
                pKeyVal[2] = (ubyte) qsKeyLen;
            }
            else if (3 == lenLen)
            {
                pKeyVal[2] = (ubyte) ((qsKeyLen >> 8) & 0xff);
                pKeyVal[3] = (ubyte) (qsKeyLen & 0xff);
            }
            else if (4 == lenLen)
            {
                pKeyVal[2] = (ubyte) ((qsKeyLen >> 16) & 0xff);
                pKeyVal[3] = (ubyte) ((qsKeyLen >> 8) & 0xff);
                pKeyVal[4] = (ubyte) (qsKeyLen & 0xff);
            }
        }
        
        status = DIGI_MEMCPY(pKeyVal + 1 + lenLen, pQSPtr, qsPrivLen);
        if (OK != status)
            goto exit;

        /* go back to where the public key was */
        pQSPtr = pQSBuffer + 4;

        status = DIGI_MEMCPY(pKeyVal + 1 + lenLen + qsPrivLen, pQSPtr, qsPubLen);
        if (OK != status)
            goto exit;
    }

    /* finally ready to create the asn1 array */
    status = MAsn1CreateElementArray (pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
    if (OK != status)
        goto exit;
    
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    
    pArray[3].value.pValue = (ubyte *) oid + 1;
    pArray[3].valueLen = oid[0];
    pArray[3].state = MASN1_STATE_SET_COMPLETE;

    if(gOqsCompatibleFormat)
    {
        pArray[4].value.pValue = pKeyVal;
        pArray[4].valueLen = 1 + lenLen + qsKeyLen;
        pArray[4].state = MASN1_STATE_SET_COMPLETE;
    } 
    else
    {
        pArray[4].value.pValue = pQSPtr;
        pArray[4].valueLen = qsPrivLen;
        pArray[4].state = MASN1_STATE_SET_COMPLETE;
    }
    
    status = MAsn1Encode (pArray, NULL, 0, &derLen);
    if (OK == status)
        status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
        goto exit;
    
    status = DIGI_MALLOC ((void **)&pDer, derLen);
    if (OK != status)
        goto exit;
    
    status = MAsn1Encode (pArray, pDer, derLen, &derLen);
    if (OK != status)
        goto exit;
    
    *ppEncoding = pDer; pDer = NULL;
    *pEncodingLen = derLen;
    
exit:
    
    if (NULL != pArray)
    {
        pArray[1].value.pValue = NULL;
        pArray[1].valueLen = 0;
        pArray[3].value.pValue = NULL;
        pArray[3].valueLen = 0;
        MAsn1FreeElementArray (&pArray);
    }
    
    if (NULL != pDer)
    {
        DIGI_MEMSET_FREE (&pDer, derLen);
    }

    if (NULL != pKeyVal)
    {
        DIGI_MEMSET_FREE (&pKeyVal, 1 + lenLen + qsKeyLen);
    }

    if (NULL != pQSBuffer)
    {
        DIGI_MEMSET_FREE (&pQSBuffer, qsBufLen);
    }
        
    return status;
}

static MSTATUS DerEncodeQsPublicKeyAlloc(QS_CTX *pCtx, ubyte **ppEncoding, ubyte4 *pEncodingLen)
{
    MSTATUS         status;
    DER_ITEMPTR     pPublicKey = NULL;
    DER_ITEMPTR     pAlgoID;
    ubyte*          pKeyBuffer = NULL;
    sbyte4          qsKeyLen;
    ubyte4          qsAlgId = 0;
    ubyte*          pOid = NULL;
    ubyte4          oidLen = 0;

    if ( (NULL == pCtx) || (NULL == ppEncoding) || (NULL == pEncodingLen) )
    {
        return ERR_NULL_POINTER;
    }

    /* get the qs Alg for the OID first */
    if (OK > ( status = CRYPTO_INTERFACE_QS_getAlg(pCtx, &qsAlgId)))
        goto exit;

    /* Get pure QS alg oid */
    if (OK > ( status = CRYPTO_getAlgoOIDAlloc(0, qsAlgId, &pOid, &oidLen)))
        goto exit;

    /* subject public key */
    if (OK > ( status = DER_AddSequence(NULL, &pPublicKey)))
        goto exit;

    /* add the algorithm identifier sequence */
    if ( OK > ( status = DER_AddSequence( pPublicKey, &pAlgoID)))
        goto exit;

    /* add the oid */
    if ( OK > ( status = DER_AddItemOwnData( pAlgoID, OID, oidLen, &pOid, NULL)))
        goto exit;

    /* allocate a buffer for the public key parameter */
    if (OK > (status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pCtx, (ubyte4 *) &qsKeyLen)))
        goto exit;

    /* add an extra byte = 0 (unused bits) */
    status = DIGI_MALLOC((void **)&pKeyBuffer, qsKeyLen + 1);
    if (OK != status)
        goto exit;

    pKeyBuffer[0] = 0; /* unused bits */

    if (OK > ( status = CRYPTO_INTERFACE_QS_getPublicKey (pCtx, pKeyBuffer + 1, qsKeyLen)))
        goto exit;

    if (OK > ( status = DER_AddItemOwnData( pPublicKey, BITSTRING, qsKeyLen + 1, &pKeyBuffer, NULL)))
        goto exit;

    /* add few extra bytes */
    *pEncodingLen = oidLen + qsKeyLen + 16;
    status = DIGI_CALLOC((void **)ppEncoding, 1, *pEncodingLen);
    if (OK != status)
        goto exit;

    /* serialize the sequence */
    if (OK > ( status = DER_SerializeInto( pPublicKey, *ppEncoding, pEncodingLen)))
        goto exit;

exit:

    if (pPublicKey)
    {
        TREE_DeleteTreeItem( (TreeItem*) pPublicKey);
    }
    if (NULL != pKeyBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBuffer, qsKeyLen + 1);
    }
    if (NULL != pOid)
    {
        (void) DIGI_MEMSET_FREE(&pOid, oidLen);
    }
    return status;
}

static MSTATUS DeserializeQsKey(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pSerializedKey, ubyte4 serializedKeyLen, AsymmetricKey *pAsymKey)
{
    MSTATUS status = ERR_CRYPTO_QS_UNSUPPORTED_CIPHER;
    MAsn1Element *pArray = NULL;
    ubyte4 bytesRead = 0;
    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;
    ubyte4 oidIndex = 3;
    ubyte4 pubIndex = 5;
    byteBoolean isPriv = TRUE;
    ubyte *pPrivBuff = NULL;
    ubyte4 privBuffLen;
    ubyte *pPubBuff = NULL;
    ubyte4 pubBuffLen;
    QS_CTX *pQsCtx = NULL;
    ubyte *pQsTmpBuff;
    ubyte *pQsBuff = NULL;
    ubyte4 qsBuffLen = 0;
    sbyte4 qsPrivLen = 0;
    ubyte4 qsPubLen = 0;
    ubyte4 qsAlgId = 0;

    MAsn1TypeAndCount pTemplate[6] =
    {
        { MASN1_TYPE_SEQUENCE, 4 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_OID, 0 },
        { MASN1_TYPE_OCTET_STRING, 0 },
        { MASN1_TYPE_BIT_STRING | MASN1_OPTIONAL | MASN1_EXPLICIT | 1, 0 }
    };

    ubyte *pKeyBuf = NULL;
    ubyte4 keyLen = 0;
    
    MAsn1Element *pOctetArray = NULL;
    MAsn1TypeAndCount pOctetTemplate[1] =
    {
        { MASN1_TYPE_OCTET_STRING, 0 },
    };

    MAsn1TypeAndCount pTemplatePub[4] =
    {
        { MASN1_TYPE_SEQUENCE, 2 },
        { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_OID, 0 },
        { MASN1_TYPE_BIT_STRING, 0 }
    };

   /* First try for a private key */
    status = MAsn1CreateElementArray (pTemplate, 6, MASN1_FNCT_DECODE, NULL, &pArray);
    if (OK != status)
      goto exit;

    status = MAsn1Decode (pSerializedKey, serializedKeyLen, pArray, &bytesRead);
    if (OK != status)
    {
        /* And finally try for a public key */
        status = MAsn1FreeElementArray (&pArray);
        if (OK != status)
            goto exit;

        status = MAsn1CreateElementArray (pTemplatePub, 4, MASN1_FNCT_DECODE, NULL, &pArray);
        if (OK != status)
            goto exit;

        status = MAsn1Decode (pSerializedKey, serializedKeyLen, pArray, &bytesRead);
        if (OK != status)
            goto exit; /* no other choices! go to exit */

        isPriv = FALSE;
        /* In public key, oid is at index 2 */
        oidIndex = 2;
        /* In public key, public key is at index 3 */
        pubIndex = 3;
    }

    pOid = pArray[oidIndex].encoding.pEncoding;
    oidLen = pArray[oidIndex].encodingLen;

    /* 0x06: OBJECT IDENTIFIER Tag number */
    if (0x06 != pOid[0])
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* skip OID Tag number and validate the rest of the oid, obtaining the curve and qsAlg if valid */
    status = CRYPTO_getQsAlgoFromOID(pOid + 2, oidLen - 2, &qsAlgId);
    if (OK != status)
        goto exit;

    if (TRUE == isPriv)
    {
        if(gOqsCompatibleFormat)
        {
            status = MAsn1CreateElementArray (pOctetTemplate, 1, MASN1_FNCT_DECODE, NULL, &pOctetArray);
            if (OK != status)
                goto exit;

            /* if isPriv == TRUE, we know 4 is the index of the private key OCTET STRING */
            status = MAsn1Decode (pArray[4].value.pValue, pArray[4].valueLen, pOctetArray, &bytesRead);
            if (OK != status)
                goto exit;

            pKeyBuf = pOctetArray[0].value.pValue;
            keyLen = pOctetArray[0].valueLen;

            status =  CRYPTO_INTERFACE_QS_getPublicKeyLenFromAlgo(qsAlgId, &qsPubLen);
            if (OK != status)
                goto exit;

            if (qsPubLen > keyLen)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            pPrivBuff = pKeyBuf;
            privBuffLen = keyLen - qsPubLen;
            pPubBuff = pKeyBuf + privBuffLen;
            pubBuffLen = qsPubLen;
        }
        else
        {
            pPrivBuff = pArray[4].value.pValue;
            privBuffLen = pArray[4].valueLen;

            /* TEMPORARY workaround for TRUSTEDGE server which (for SLH-DSA) still
               sends an OCTET_STRING within an OCTET_STRING, skip into inner octet string */
            if (qsAlgId >= cid_PQC_SLHDSA_SHA2_128S && (66 == privBuffLen || 98 == privBuffLen)) /* 2 extra bytes for 128 or 192 */
            {
                pPrivBuff += 2;
                privBuffLen -= 2;
            }
            else if (qsAlgId >= cid_PQC_SLHDSA_SHA2_128S && (131 == privBuffLen)) /* 3 for 256 */
            {
                pPrivBuff += 3;
                privBuffLen -= 3;
            }

            pPubBuff = pArray[pubIndex].value.pValue;
            pubBuffLen = pArray[pubIndex].valueLen;

            if (pubBuffLen > 0)
            {
                /* skip 0x00 byte of BITSTRING type buffer */
                qsPubLen = pubBuffLen - 1;
            }
        }
    }
    else
    {
        pPubBuff = pArray[pubIndex].value.pValue;
        pubBuffLen = pArray[pubIndex].valueLen;

        /* Deserializaing public key, must have public portion */
        if (0 == pubBuffLen)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if (TRUE == gOqsCompatibleFormat)
        {
            qsPubLen = pubBuffLen;
        }
        else
        {
            qsPubLen = pubBuffLen - 1;
        }
    }

    /* calculate total length of QS buffer */

    if (TRUE == isPriv)
    {
        qsPrivLen = privBuffLen;
        qsBuffLen = 4 + qsPubLen + 4 + qsPrivLen;
    }
    else
    {
        qsBuffLen = 4 + qsPubLen;
    }

    status = DIGI_MALLOC((void **) &pQsBuff, qsBuffLen);
    if (OK != status)
        goto exit;

    pQsTmpBuff = pQsBuff;
    pQsTmpBuff[0] = (ubyte)(qsPubLen >> 24);
    pQsTmpBuff[1] = (ubyte)(qsPubLen >> 16);
    pQsTmpBuff[2] = (ubyte)(qsPubLen >> 8);
    pQsTmpBuff[3] = (ubyte)(qsPubLen);

    pQsTmpBuff += 4;

    if (qsPubLen > 0)
    {
        /* skip past 0x00 byte for bitstring non-compat format */
        status = DIGI_MEMCPY(pQsTmpBuff, pPubBuff + (gOqsCompatibleFormat ? 0 : 1), qsPubLen);
        if (OK != status)
            goto exit;

        pQsTmpBuff += qsPubLen;
    }

    if (TRUE == isPriv)
    {
        pQsTmpBuff[0] = (ubyte)(qsPrivLen >> 24);
        pQsTmpBuff[1] = (ubyte)(qsPrivLen >> 16);
        pQsTmpBuff[2] = (ubyte)(qsPrivLen >> 8);
        pQsTmpBuff[3] = (ubyte)(qsPrivLen);

        pQsTmpBuff += 4;

        status = DIGI_MEMCPY(pQsTmpBuff, pPrivBuff, qsPrivLen);
        if (OK != status)
            goto exit;
    }
    pQsTmpBuff = NULL;

    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, qsAlgId);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_deserializeKey(pQsCtx,
                    isPriv ? MOC_ASYM_KEY_TYPE_PRIVATE : MOC_ASYM_KEY_TYPE_PUBLIC,
                    pQsBuff, qsBuffLen);
    if (OK != status)
        goto exit;

    pQsCtx->isPrivate = isPriv;

    pAsymKey->type = akt_qs;
    pAsymKey->pQsCtx = pQsCtx;
    pQsCtx = NULL;

exit:

    if (NULL != pQsCtx)
        CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);

    if (NULL != pQsBuff)
        DIGI_FREE((void **) &pQsBuff);

    if (NULL != pArray)
        MAsn1FreeElementArray (&pArray);

    if (NULL != pOctetArray)
        MAsn1FreeElementArray (&pOctetArray);

    return status;
}

static MSTATUS SerializeQsKeyAlloc(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey, serializedKeyFormat keyFormat, ubyte **ppSerializedKey, ubyte4 *pSerializedKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    QS_CTX *pCtx = NULL;
    
    if (NULL == pAsymKey)  /* other params will be checked for NULL in below calls */
        goto exit;
    
    /* caller already checked type to be akt_qs */
    pCtx = pAsymKey->pQsCtx;
    
    if (NULL == pCtx)
        goto exit;
    
    /* If requesting a blob, get a blob.
     */
    if (mocanaBlobVersion2 == keyFormat)
    {
        status = KEYBLOB_makeQsBlob(MOC_ASYM(hwAccelCtx) pCtx, ppSerializedKey, pSerializedKeyLen);
        goto exit;
    }

    /* At this point, the format should be either pub key or pri key DER. We don't
     * build PEM directly, the contents of PEM is the DER and the caller should
     * take care of the PEM with any DER.
     * Build the DER of the key data.
     * But first, make sure the format matches.
     * Use the QS context to determine if it's private.
     */

    status = ERR_INVALID_INPUT;
    if (privateKeyInfoDer == keyFormat || privateKeyPem == keyFormat)
    {
        if (!pCtx->isPrivate)
            goto exit;

        status = DerEncodeQsPrivateKeyAlloc(pCtx, ppSerializedKey, pSerializedKeyLen);
    }
    else if (publicKeyInfoDer == keyFormat || publicKeyPem == keyFormat)
    {
        status = DerEncodeQsPublicKeyAlloc(pCtx, ppSerializedKey, pSerializedKeyLen);
    }

exit:
    
    return status;
}

extern MSTATUS KeySerializeQs (
    MOC_ASYM(hwAccelDescr hwAccelCtx) 
    AsymmetricKey *pAsymKey,
    serializedKeyFormat keyFormat,
    ubyte **ppSerializedKey,
    ubyte4 *pSerializedKeyLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 keyType = 0, version = 0;
    
    if ( NULL == pAsymKey || NULL == ppSerializedKey || NULL == pSerializedKeyLen )
        goto exit;
    
    if (deserialize == keyFormat)
    {
        if ( NULL == *ppSerializedKey || 0 == *pSerializedKeyLen )
            goto exit;
        
        if (0x00 == (*ppSerializedKey)[0])
        {
            status = KEYBLOB_parseHeader(*ppSerializedKey, *pSerializedKeyLen, &keyType, &version);
            if (OK != status)
                goto exit;
            
            status = ERR_BAD_KEY_BLOB;
            if (akt_qs != keyType)
            {
                goto exit;
            }
            
            status = KEYBLOB_extractKeyBlobEx(*ppSerializedKey, *pSerializedKeyLen, pAsymKey);
        }
        else
        {
            /* Deserialization PKCS8 keys only works for NIST curves, edDSA 25519 and edDSA 448 keys not supported */
            status = DeserializeQsKey(MOC_HASH(hwAccelCtx) *ppSerializedKey, *pSerializedKeyLen, pAsymKey);
        }
    }
    else /* serialize */
    {
        /* Before serializing, make sure the type is qs. */
        status = ERR_BAD_KEY;
        if (akt_qs != pAsymKey->type)
            goto exit;
        
        status = SerializeQsKeyAlloc(MOC_ASYM(hwAccelCtx) pAsymKey, keyFormat, ppSerializedKey, pSerializedKeyLen);
    }
    
exit:
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_PQC__) */
