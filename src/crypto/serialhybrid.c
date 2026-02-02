/*
 * serialhybrid.c
 *
 * Serialize Hybrid keys.
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

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_PQC__)

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
#include "../crypto/mocasymkeys/mocsw/commonrsa.h"

#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/mocasn1.h"

#include "../crypto_interface/crypto_interface_ecc.h"
#include "../crypto_interface/crypto_interface_qs.h"

static MSTATUS DerEncodeHybridPrivateKeyAlloc(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte **ppEncoding, ubyte4 *pEncodingLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte version = 1; /* version 1 is with public key bitstring */
    ubyte *pPubVal = NULL;
    ubyte *pPriVal = NULL;
    ubyte *pDer = NULL;
    ubyte4 derLen = 0;
    
    MEccKeyTemplate keyTemplate = {0};
    byteBoolean isFreeECCtemplate = FALSE;
    
    ubyte *pQSBuffer = NULL;
    ubyte *pQSPtr = NULL;
    ubyte4 qsBufLen = 0;
    ubyte4 qsPrivLen = 0;
    ubyte4 qsPubLen = 0;
    ubyte4 totalPrivLen = 0;
    ubyte4 totalPubLen = 0;
    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;
    ubyte4 qsAlgId = 0;
    ubyte *pRsaSer = NULL;
    ubyte4 rsaSerLen = 0;
    ubyte *pRsaPubSer = NULL;
    ubyte4 rsaPubSerLen = 0;

    MAsn1Element *pArray = NULL;

    MAsn1TypeAndCount pTemplate[6] =
    {
        { MASN1_TYPE_SEQUENCE, 4 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_OID, 0 },
        { MASN1_TYPE_OCTET_STRING, 0 },
        { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | 1, 0 }
    };
    
    if (NULL == ppEncoding || NULL == pEncodingLen) /* other input params already checked */
        goto exit;
        
    /* get the oid for the hybrid alg in question first */
    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = CRYPTO_getAlgoOIDAlloc(pKey->clAlg, qsAlgId, &pOid, &oidLen);
    if (OK != status)
        goto exit;

    /* get the QS parameters, serialize the secret key so we have access to both the private (secret) and public keys */
    status = CRYPTO_INTERFACE_QS_serializeKeyAlloc(pKey->pQsCtx, MOC_ASYM_KEY_TYPE_PRIVATE, &pQSBuffer, &qsBufLen);
	if (OK != status)
		goto exit;

    /* we check the validity of the qsBuffer as we go */
    status = ERR_INTERNAL_ERROR;
    if (qsBufLen < 8)
        goto exit;
    
    /* public key is first! */
    pQSPtr = pQSBuffer;
    
    qsPubLen = (pQSPtr[0] << 24) | (pQSPtr[1] << 16) | (pQSPtr[2] << 8) | pQSPtr[3];
    pQSPtr += 4;
    
    if (qsBufLen < 8 + qsPubLen)
        goto exit;

    pQSPtr += qsPubLen;

    qsPrivLen = (pQSPtr[0] << 24) | (pQSPtr[1] << 16) | (pQSPtr[2] << 8) | pQSPtr[3];
    pQSPtr += 4;
    
    if (8 + qsPubLen + qsPrivLen > qsBufLen)
        goto exit;

    if (pKey->clAlg < cid_RSA_2048_PKCS15) /* ECC */
    {
        /* get the ECC parameters next */
        status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(MOC_ECC(hwAccelCtx) pKey->key.pECC, &keyTemplate, MOC_GET_PRIVATE_KEY_DATA);
        if (OK != status)
            goto exit;

        totalPrivLen = 4 + qsPrivLen + keyTemplate.privateKeyLen; /* 4 byte length prefix */
        totalPubLen = 5 + qsPubLen + keyTemplate.publicKeyLen;
        isFreeECCtemplate = TRUE;
    }
    else /* RSA */
    {
        status = SerializeRsaKeyAlloc ( MOC_ASYM(hwAccelCtx) pKey, privateKeyInfoDer, &pRsaSer, &rsaSerLen);
        if (OK != status)
            goto exit;

        status = SerializeRsaKeyAlloc( MOC_ASYM(hwAccelCtx) pKey, publicKeyInfoDer, &pRsaPubSer, &rsaPubSerLen);
        if (OK != status)
            goto exit;

        totalPrivLen = 4 + qsPrivLen + rsaSerLen; /* 4 byte length prefix */
        totalPubLen = 5 + qsPubLen + rsaPubSerLen; /* BITSTRING, add initial 0x00 byte, and 4 byte length */
    }

    status = DIGI_MALLOC((void **) &pPriVal, totalPrivLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pPubVal, totalPubLen);
    if (OK != status)
        goto exit;

    /* Little endian 4 byte lengths */
    pPriVal[0] = (ubyte) (qsPrivLen & 0xff);
    pPriVal[1] = (ubyte) ((qsPrivLen >> 8) & 0xff); 
    pPriVal[2] = (ubyte) ((qsPrivLen >> 16) & 0xff); 
    pPriVal[3] = (ubyte) ((qsPrivLen >> 24) & 0xff); 

    status = DIGI_MEMCPY(pPriVal + 4, pQSPtr, qsPrivLen);
    if (OK != status)
        goto exit;

    pPubVal[0] = 0;
    pPubVal[1] = (ubyte) (qsPubLen & 0xff);
    pPubVal[2] = (ubyte) ((qsPubLen >> 8) & 0xff); 
    pPubVal[3] = (ubyte) ((qsPubLen >> 16) & 0xff); 
    pPubVal[4] = (ubyte) ((qsPubLen >> 24) & 0xff); 

    status = DIGI_MEMCPY(pPubVal + 5, pQSBuffer + 4, qsPubLen); /* public key starts after the 4 byte length */
    if (OK != status)
        goto exit;

    if (pKey->clAlg < cid_RSA_2048_PKCS15) /* ECC */
    {
        status = DIGI_MEMCPY(pPriVal + 4 + qsPrivLen, keyTemplate.pPrivateKey, keyTemplate.privateKeyLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pPubVal + 5 + qsPubLen, keyTemplate.pPublicKey, keyTemplate.publicKeyLen);
        if (OK != status)
            goto exit; 
    }
    else /* RSA */
    {
        status = DIGI_MEMCPY(pPriVal + 4 + qsPrivLen, pRsaSer, rsaSerLen);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pPubVal + 5 + qsPubLen, pRsaPubSer, rsaPubSerLen); 
        if (OK != status)
            goto exit;
    }
    
    /* finally ready to create the asn1 array */
    status = MAsn1CreateElementArray (pTemplate, 6, MASN1_FNCT_ENCODE, NULL, &pArray);
    if (OK != status)
        goto exit;
    
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    
    pArray[3].value.pValue = (ubyte *) pOid;
    pArray[3].valueLen = oidLen;
    pArray[3].state = MASN1_STATE_SET_COMPLETE;
    
    pArray[4].value.pValue = pPriVal;
    pArray[4].valueLen = totalPrivLen;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;
    
    pArray[5].value.pValue = pPubVal;
    pArray[5].valueLen = totalPubLen;
    pArray[5].state = MASN1_STATE_SET_COMPLETE;
    
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
        MAsn1FreeElementArray (&pArray);
    }
    
    if (NULL != pDer)
    {
        DIGI_MEMSET_FREE (&pDer, derLen);
    }
    
    if (NULL != pPriVal)
    {
        DIGI_MEMSET_FREE (&pPriVal, totalPrivLen);
    }
    
    if (NULL != pPubVal)
    {
        DIGI_MEMSET_FREE (&pPubVal, totalPubLen);
    }
    
    if (NULL != pQSBuffer)
    {
        DIGI_MEMSET_FREE (&pQSBuffer, qsBufLen);
    }

    if (NULL != pOid)
    {
        DIGI_MEMSET_FREE(&pOid, oidLen);
    }
    
    if (isFreeECCtemplate)
    {
        (void) EC_freeKeyTemplate(pKey->key.pECC, &keyTemplate);
    }

    if (NULL != pRsaSer)
    {
        (void) DIGI_MEMSET_FREE(&pRsaSer, rsaSerLen);
    }

    if (NULL != pRsaPubSer)
    {
        (void) DIGI_MEMSET_FREE (&pRsaPubSer, rsaPubSerLen);
    }

    return status;
}

static MSTATUS DerEncodeHybridPublicKeyAlloc(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte **ppEncoding, ubyte4 *pEncodingLen)
{
    return ERR_NOT_IMPLEMENTED;
}

static MSTATUS DeserializeHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pSerializedKey, ubyte4 serializedKeyLen, AsymmetricKey *pAsymKey)
{
    MSTATUS status = OK;
    MAsn1Element *pArray = NULL;
    ubyte4 bytesRead = 0;
    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;
    ubyte4 oidIndex = 3;
    ubyte4 pubIndex = 5; 
    ubyte *pPrivBuff = NULL;
    ubyte4 privBuffLen = 0;
    ubyte *pPubBuff = NULL;
    ubyte4 pubBuffLen = 0;
    QS_CTX *pQsCtx = NULL;
    ubyte4 qsPrivLen = 0;
    ECCKey *pEccKey = NULL;
    ubyte4 qsPubLen = 0;
    ubyte4 clAlgId = 0;
    ubyte4 qsAlgId = 0;
    ubyte *pQsBuff = NULL;
    ubyte *pQsTmpBuff = NULL;
    ubyte4 qsBuffLen = 0;

    MAsn1TypeAndCount pTemplate[6] =
    {
        { MASN1_TYPE_SEQUENCE, 4 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_SEQUENCE, 1 },
        { MASN1_TYPE_OID, 0 },
        { MASN1_TYPE_OCTET_STRING, 0 },
        { MASN1_TYPE_BIT_STRING | MASN1_OPTIONAL | MASN1_EXPLICIT | 1, 0 }
    };

    status = MAsn1CreateElementArray (pTemplate, 6, MASN1_FNCT_DECODE, NULL, &pArray);
    if (OK != status)
      goto exit;

    status = MAsn1Decode (pSerializedKey, serializedKeyLen, pArray, &bytesRead);
    if (OK != status)
        goto exit;

    pOid = pArray[oidIndex].encoding.pEncoding;
    oidLen = pArray[oidIndex].encodingLen;

    /* 0x06: OBJECT IDENTIFIER Tag number */
    if (0x06 != pOid[0])
    {
        status = ERR_INVALID_INPUT;    
        goto exit;
    }

    /* skip OID Tag number and validate the rest of the oid, obtaining the curve and qsAlg if valid */
    status = CRYPTO_getHybridCurveAlgoFromOID(pOid + 2, oidLen - 2, &clAlgId, &qsAlgId);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, qsAlgId);
    if (OK != status)
        goto exit;

    pPrivBuff = pArray[4].value.pValue;
    privBuffLen = pArray[4].valueLen;

    pPubBuff = pArray[pubIndex].value.pValue;
    pubBuffLen = pArray[pubIndex].valueLen;

    /* check the initial length of qs keys */
    qsPrivLen = ((ubyte4) pPrivBuff[0]) | (((ubyte4)pPrivBuff[1]) << 8) | 
               (((ubyte4)pPrivBuff[2]) << 16) | (((ubyte4)pPrivBuff[3]) << 24);

    if (NULL != pPubBuff && pubBuffLen >= 5)
    {
        qsPubLen = ((ubyte4) pPubBuff[1]) | (((ubyte4)pPubBuff[2]) << 8) | 
                   (((ubyte4)pPubBuff[3]) << 16) | (((ubyte4)pPubBuff[4]) << 24);

        qsBuffLen = 4 + qsPubLen + 4 + qsPrivLen;
    
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
            status = DIGI_MEMCPY(pQsTmpBuff, pPubBuff + 5, qsPubLen);
            if (OK != status)
                goto exit;
    
            pQsTmpBuff += qsPubLen;
        }
    
        pQsTmpBuff[0] = (ubyte)(qsPrivLen >> 24);
        pQsTmpBuff[1] = (ubyte)(qsPrivLen >> 16);
        pQsTmpBuff[2] = (ubyte)(qsPrivLen >> 8);
        pQsTmpBuff[3] = (ubyte)(qsPrivLen);
    
        pQsTmpBuff += 4;

        status = DIGI_MEMCPY(pQsTmpBuff, pPrivBuff + 4, qsPrivLen);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_deserializeKey(pQsCtx, MOC_ASYM_KEY_TYPE_PRIVATE, pQsBuff, qsBuffLen);
        if (OK != status)
            goto exit;
    }
    else /* we didn't have a valid public key, just set the private key, eventually one of these 2 flows will win out */
    {
        status = CRYPTO_INTERFACE_QS_setPrivateKey(pQsCtx, pPrivBuff + 4, qsPrivLen);
        if (OK != status)
            goto exit;
    }
     
    if (clAlgId < cid_RSA_2048_PKCS15) /* ECC */
    {
        status = CRYPTO_INTERFACE_EC_newKeyAux(clAlgId, &pEccKey);
        if (OK != status)
          goto exit;
        
        if (pubBuffLen > 5 + qsPubLen)
        {
            status = CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) pEccKey, pPubBuff + 5 + qsPubLen, pubBuffLen - 5 - qsPubLen, 
                                                             pPrivBuff + 4 + qsPrivLen, privBuffLen - 4 - qsPrivLen);
        }
        else /* private key only. Eventually remove? */
        {
            status = CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) pEccKey, NULL, 0, 
                                                             pPrivBuff + 4 + qsPrivLen, privBuffLen - 4 - qsPrivLen);            
        }
        if (OK != status)
            goto exit;

        pAsymKey->key.pECC = pEccKey; pEccKey = NULL;
    }
    else /* RSA */
    {
        /* this should deserialize public key too as part of the private serialization */
        status = DeserializeRsaKey(MOC_ASYM(hwAccelCtx) pPrivBuff + 4 + qsPrivLen, privBuffLen - 4 - qsPrivLen, pAsymKey, NULL);
        if (OK != status)
            goto exit;

        /* Potentially later: deserialize the RSA pub out of the compositePublicKeyInfo and compare that it matches */
    }

    /* change type to hybrid */
    pAsymKey->type = akt_hybrid;
    pAsymKey->pQsCtx = pQsCtx; pQsCtx = NULL;
    pAsymKey->clAlg = clAlgId;

exit:

    /* allocation of an RSA key is final step for those, no cleanup necc */
    if (NULL != pEccKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pEccKey);
    }
    if (NULL != pQsCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);
    }
    if (NULL != pArray)
    {
        (void) MAsn1FreeElementArray (&pArray);
    }
    if (NULL != pQsBuff)
    {
        (void) DIGI_MEMSET_FREE(&pQsBuff, qsBuffLen);
    }

    return status;
}

static MSTATUS SerializeHybridKeyAlloc(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pAsymKey, serializedKeyFormat keyFormat, ubyte **ppSerializedKey, ubyte4 *pSerializedKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pAsymKey)  /* other params will be checked for NULL in below calls */
        goto exit;
    
    /* caller already checked type to be akt_hybrid */

    /* If requesting a blob, get a blob.
     */
    if (mocanaBlobVersion2 == keyFormat)
    {
        status = KEYBLOB_makeHybridBlob(MOC_ASYM(hwAccelCtx) pAsymKey, ppSerializedKey, pSerializedKeyLen);
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
        if (!pAsymKey->pQsCtx->isPrivate)
            goto exit;

        status = DerEncodeHybridPrivateKeyAlloc(MOC_ASYM(hwAccelCtx) pAsymKey, ppSerializedKey, pSerializedKeyLen);
    }
    else if (publicKeyInfoDer == keyFormat || publicKeyPem == keyFormat)
    {
        status = DerEncodeHybridPublicKeyAlloc(MOC_ASYM(hwAccelCtx) pAsymKey, ppSerializedKey, pSerializedKeyLen);
    }

exit:
    
    return status;
}

extern MSTATUS KeySerializeHybrid (
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
            if (akt_hybrid != keyType)
            {
                goto exit;
            }
            
            status = KEYBLOB_extractKeyBlobEx(*ppSerializedKey, *pSerializedKeyLen, pAsymKey);
        }
        else
        {
            /* Deserialization PKCS8 keys only works for NIST curves, edDSA 25519 and edDSA 448 keys not supported */
            status = DeserializeHybridKey(MOC_ASYM(hwAccelCtx) *ppSerializedKey, *pSerializedKeyLen, pAsymKey);
        }
    }
    else /* serialize */
    {
        /* Before serializing, make sure the type is hybrid. */
        status = ERR_BAD_KEY;
        if (akt_hybrid != pAsymKey->type)
            goto exit;
        
        status = SerializeHybridKeyAlloc(MOC_ASYM(hwAccelCtx) pAsymKey, keyFormat, ppSerializedKey, pSerializedKeyLen);
    }
    
exit:
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_PQC__) */
