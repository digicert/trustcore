/*
 * crypto_interface_sym_tap.c
 *
 * Cryptographic Interface specification for Generic Symmetric TAP.
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

#include "../crypto/mocsym.h"
#include "../common/debug_console.h"
#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../asn1/mocasn1.h"
#include "../crypto/aes.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto/mocsymalgs/tap/symtap.h"

/*---------------------------------------------------------------------------*/

typedef struct
{
    ubyte *pAlgId;
    ubyte4 algIdLen;
    cryptoInterfaceSymAlgo symAlgo;
    ubyte4 keyType;
} AlgIdHelper;

/*---------------------------------------------------------------------------*/

/* Alg id for mode-less AES key */
static ubyte pAesAlgId[MOP_AES_TAP_KEY_ALG_ID_LEN] =
{
    MOP_AES_TAP_KEY_ALG_ID
};

/* Alg ids for mode-bound AES keys */
static ubyte pAesEcbAlgId[MOP_AES_ECB_TAP_KEY_ALG_ID_LEN] =
{
    MOP_AES_ECB_TAP_KEY_ALG_ID
};

static ubyte pAesCbcAlgId[MOP_AES_CBC_TAP_KEY_ALG_ID_LEN] =
{
    MOP_AES_CBC_TAP_KEY_ALG_ID
};

static ubyte pAesCfbAlgId[MOP_AES_CFB_TAP_KEY_ALG_ID_LEN] =
{
    MOP_AES_CFB_TAP_KEY_ALG_ID
};

static ubyte pAesOfbAlgId[MOP_AES_OFB_TAP_KEY_ALG_ID_LEN] =
{
    MOP_AES_OFB_TAP_KEY_ALG_ID
};

static ubyte pAesCtrAlgId[MOP_AES_CTR_TAP_KEY_ALG_ID_LEN] =
{
    MOP_AES_CTR_TAP_KEY_ALG_ID
};

static ubyte pAesGcmAlgId[MOP_AES_GCM_TAP_KEY_ALG_ID_LEN] =
{
    MOP_AES_GCM_TAP_KEY_ALG_ID
};

/* Alg id for mode-less DES key */
static ubyte pDesAlgId[MOP_DES_TAP_KEY_ALG_ID_LEN] =
{
    MOP_DES_TAP_KEY_ALG_ID
};

/* Alg ids for mode-bound DES keys */
static ubyte pDesEcbAlgId[MOP_DES_ECB_TAP_KEY_ALG_ID_LEN] =
{
    MOP_DES_ECB_TAP_KEY_ALG_ID
};

static ubyte pDesCbcAlgId[MOP_DES_CBC_TAP_KEY_ALG_ID_LEN] =
{
    MOP_DES_CBC_TAP_KEY_ALG_ID
};

/* Alg id for mode-less TDES key */
static ubyte pTDesAlgId[MOP_TDES_TAP_KEY_ALG_ID_LEN] =
{
    MOP_TDES_TAP_KEY_ALG_ID
};

/* Alg ids for mode-bound TDES keys */
static ubyte pTDesEcbAlgId[MOP_TDES_ECB_TAP_KEY_ALG_ID_LEN] =
{
    MOP_TDES_ECB_TAP_KEY_ALG_ID
};

static ubyte pTDesCbcAlgId[MOP_TDES_CBC_TAP_KEY_ALG_ID_LEN] =
{
    MOP_TDES_CBC_TAP_KEY_ALG_ID
};

/* Alg id for HMAC keys */
static ubyte pHmacAlgId[MOP_HMAC_TAP_KEY_ALG_ID_LEN] =
{
    MOP_HMAC_TAP_KEY_ALG_ID
};

/*---------------------------------------------------------------------------*/

/* It is intentional that all AES share the same moc_alg_aes. There is only one
 * operator which is modeless, the mode-binding occurs at the CI TAP layer through
 * keyType validation at load time */
static AlgIdHelper pSupportedAlgsInfo[] =
{
    { pAesAlgId, MOP_AES_TAP_KEY_ALG_ID_LEN, moc_alg_aes, MOC_SYM_ALG_AES },
    { pAesEcbAlgId, MOP_AES_ECB_TAP_KEY_ALG_ID_LEN, moc_alg_aes, MOC_SYM_ALG_AES_ECB },
    { pAesCbcAlgId, MOP_AES_CBC_TAP_KEY_ALG_ID_LEN, moc_alg_aes, MOC_SYM_ALG_AES_CBC },
    { pAesCfbAlgId, MOP_AES_CFB_TAP_KEY_ALG_ID_LEN, moc_alg_aes, MOC_SYM_ALG_AES_CFB },
    { pAesOfbAlgId, MOP_AES_OFB_TAP_KEY_ALG_ID_LEN, moc_alg_aes, MOC_SYM_ALG_AES_OFB },
    { pAesCtrAlgId, MOP_AES_CTR_TAP_KEY_ALG_ID_LEN, moc_alg_aes, MOC_SYM_ALG_AES_CTR },
    { pAesGcmAlgId, MOP_AES_GCM_TAP_KEY_ALG_ID_LEN, moc_alg_aes, MOC_SYM_ALG_AES_GCM },
    { pDesAlgId, MOP_DES_TAP_KEY_ALG_ID_LEN, moc_alg_des, MOC_SYM_ALG_DES },
    { pDesEcbAlgId, MOP_DES_ECB_TAP_KEY_ALG_ID_LEN, moc_alg_des_ecb, MOC_SYM_ALG_DES_ECB },
    { pDesCbcAlgId, MOP_DES_CBC_TAP_KEY_ALG_ID_LEN, moc_alg_des_cbc, MOC_SYM_ALG_DES_CBC },
    { pTDesAlgId, MOP_TDES_TAP_KEY_ALG_ID_LEN, moc_alg_tdes, MOC_SYM_ALG_TDES },
    { pTDesEcbAlgId, MOP_TDES_ECB_TAP_KEY_ALG_ID_LEN, moc_alg_tdes_ecb, MOC_SYM_ALG_TDES_ECB },
    { pTDesCbcAlgId, MOP_TDES_CBC_TAP_KEY_ALG_ID_LEN, moc_alg_tdes_cbc, MOC_SYM_ALG_TDES_CBC },
    { pHmacAlgId, MOP_HMAC_TAP_KEY_ALG_ID_LEN, moc_alg_hmac, MOC_SYM_ALG_HMAC }
};

static ubyte4 numAlgos = 14;

#endif /* ifdef __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GenerateSymKey (
    SymmetricKey **ppNewKey,
    sbyte4 keyLenBits,
    void *pOpInfo
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED, index = 0;
    MocSymCtx pNewSymCtx = NULL;
    SymmetricKey *pNewKey = NULL;
    MocCtx pMocCtx = NULL;
    MSymTapKeyGenArgs *pKeyGenArgs = NULL;
    ubyte4 keyType = 0;
    MSymOperator operator = MAesTapOperator;
    cryptoInterfaceSymAlgo symAlgo = moc_alg_aes;

    if ( (NULL == ppNewKey) || (NULL == pOpInfo) )
        goto exit;

    pKeyGenArgs = (MSymTapKeyGenArgs *) pOpInfo;
    switch (pKeyGenArgs->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:

            /* operator and symAlgo arleady are MAesTapOperator and moc_alg_aes by default */

            switch (pKeyGenArgs->symMode)
            {
                case TAP_SYM_KEY_MODE_CTR:
                    keyType = MOC_SYM_ALG_AES_CTR;
                    break;

                case TAP_SYM_KEY_MODE_OFB:
                    keyType = MOC_SYM_ALG_AES_OFB;
                    break;

                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_AES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_CFB:
                    keyType = MOC_SYM_ALG_AES_CFB;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_AES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_GCM:
                    keyType = MOC_SYM_ALG_AES_GCM;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_AES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_AES;
                    break;
            }
            break;

        case TAP_KEY_ALGORITHM_DES:

            operator = MDesTapOperator;
            symAlgo = moc_alg_des;

            switch (pKeyGenArgs->symMode)
            {
                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_DES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_DES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_DES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_DES;
                    break;
            }
            break;

        case TAP_KEY_ALGORITHM_TDES:

            operator = MTDesTapOperator;
            symAlgo = moc_alg_tdes;

            switch (pKeyGenArgs->symMode)
            {
                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_TDES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_TDES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_TDES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_TDES;
                    break;
            }
            break;

        case TAP_KEY_ALGORITHM_HMAC:

            operator = MHmacTapOperator;
            symAlgo = moc_alg_hmac;
            keyType = MOC_SYM_ALG_HMAC;
            break;

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    status = CRYPTO_INTERFACE_checkTapSymAlgoStatus(symAlgo, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
        goto exit;
    }

    /* Get a reference to the Tap MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getTapMocCtx(&pMocCtx);
    if (OK != status)
        goto exit;

    status = CRYPTO_generateSymKeyEx (operator, pMocCtx, &pNewSymCtx, keyLenBits, pOpInfo);
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(SymmetricKey));
    if (OK != status)
        goto exit;

    /* Load the MocSymCtx into the SymmetricKey wrapper */
    pNewKey->pKeyData = (void *) pNewSymCtx; pNewSymCtx = NULL;
    pNewKey->keyType = keyType;
    /* isDeferUnload flag is already set to FALSE */

    /* Give caller ownership of new SymmetricKey */
    *ppNewKey = pNewKey; pNewKey = NULL;

exit:

    if (NULL != pNewKey)
    {
        (void) DIGI_FREE((void **)&pNewKey);
    }

    if (NULL != pNewSymCtx)
    {
        (void) CRYPTO_freeMocSymCtx (&pNewSymCtx);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymDeferUnload (
    MocSymCtx pCtx,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    if (NULL == pCtx || NULL == pCtx->pLocalData)
        return ERR_NULL_POINTER;

    ((MTapKeyData *)(pCtx->pLocalData))->isDeferUnload = TRUE;

    if (TRUE == deferredTokenUnload)
    {
        if (NULL == ((MTapKeyData *)(pCtx->pLocalData))->pKey)
        {
            return ERR_NULL_POINTER;
        }

        ((MTapKeyData *)(pCtx->pLocalData))->pKey->deferredTokenUnload = TRUE;
    }

    return OK;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymGetKeyInfo (
    MocSymCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MTapKeyData *pTapData = NULL;
    TAP_Key *pTapKey = NULL;

    if (NULL == pCtx || NULL == pTokenHandle || NULL == pKeyHandle || NULL == pCtx->pLocalData)
        goto exit;

    status = ERR_TAP_INVALID_KEY_TYPE;
    if ( 0 == (MOC_LOCAL_TYPE_TAP & pCtx->localType) )
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *) pTapData->pKey;

    if (pTapData->isKeyLoaded)
    {
        *pTokenHandle = pTapKey->tokenHandle;
        *pKeyHandle = pTapKey->keyHandle;

         status = OK;
    }
    else
    {
        *pTokenHandle = 0;
        *pKeyHandle = 0;

        status = ERR_TAP_KEY_NOT_INITIALIZED;
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymKeyDeferUnload (
    SymmetricKey *pKey,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    if (NULL == pKey)
        return ERR_NULL_POINTER;

    return CRYPTO_INTERFACE_TAP_SymDeferUnload((MocSymCtx) pKey->pKeyData, deferredTokenUnload);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_serializeSymKey(
    SymmetricKey *pKey,
    ubyte **ppSerializedKey,
    ubyte4 *pSerializedKeyLen
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER, status2 = OK;
    MTapKeyData *pTapData = NULL;
    ubyte *pAlgId = NULL;
    ubyte4  algIdLen = 0;
    ubyte *pSerKey = NULL;
    ubyte4 serKeyLen = 0;
    MocSymCtx pSymCtx = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Buffer serKey = {0};
    ubyte4 i = 0;

    MAsn1Element *pArray = NULL;

    /* For the Symmetric TAP Key, build
     * SEQ {
     *   Version version,
     *   ModuleId moduleId,
     *   TapPrivateKey tapPrivateKey
     * }
     *
     * where
     * Version ::= INTEGER { v1(0) } (v1,...)
     * ModuleId ::= INTEGER { tpm2-1-2(1), tpm2-0(2) } (tpm-1-2, tpm-2-0, ...)
     * TapPrivateKey ::= OCTET STRING
     */
    MAsn1TypeAndCount pTemplate[4] =
    {
        { MASN1_TYPE_SEQUENCE, 3 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_OCTET_STRING, 0 }
    };

    if (NULL == pKey || NULL == pKey->pKeyData || NULL == ppSerializedKey || NULL == pSerializedKeyLen)
        goto exit;

    pSymCtx = (MocSymCtx)pKey->pKeyData;
    pTapData = (MTapKeyData *)pSymCtx->pLocalData;

    status = ERR_NULL_POINTER;
    if (NULL == pTapData)
        goto exit;

    /* key must be in a loaded form to serialize */
    if (!pTapData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapData->pTapCtx, pTapData->pEntityCredentials, pTapData->pKey, pTapData->pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit;

        pTapData->isKeyLoaded = TRUE;
    }

    for (i = 0; i < numAlgos; i++)
    {
        if (pSupportedAlgsInfo[i].keyType == pKey->keyType)
        {
            pAlgId = pSupportedAlgsInfo[i].pAlgId;
            algIdLen = pSupportedAlgsInfo[i].algIdLen;
            break;
        }
    }

    status = ERR_INVALID_INPUT;
    if ( (NULL == pAlgId) || (0 == algIdLen) )
    {
        goto exit;
    }

    status = MAsn1CreateElementArray (pTemplate, 4, MASN1_FNCT_ENCODE, NULL, &pArray);
    if (OK != status)
        goto exit;

    /* Set the Version */
    status = MAsn1SetInteger (pArray + 1, NULL, 0, TRUE, 0);
    if (OK != status)
        goto exit;

    /* Set the Module Id */
    status = MAsn1SetInteger (pArray + 2, NULL, 0, TRUE, (sbyte4)pTapData->pKey->providerObjectData.objectInfo.moduleId);
    if (OK != status)
        goto exit;

    status = TAP_serializeKey(pTapData->pKey, TAP_BLOB_FORMAT_MOCANA, TAP_BLOB_ENCODING_BINARY, &serKey, pErrContext);
    if (OK != status)
        goto exit;

    /* Put the serialized TAP key blob into the octet string for encoding */
    status = MAsn1SetValue(pArray + 3, serKey.pBuffer, serKey.bufferLen);
    if (OK != status)
        goto exit;

    /* Get the encoding length */
    status = MAsn1Encode (pArray, NULL, 0, &serKeyLen);
    if (OK == status)
        status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
        goto exit;

    /* Allocate space for the encoding */
    status = DIGI_MALLOC ((void **)&pSerKey, serKeyLen);
    if (OK != status)
        goto exit;

    /* Get the ASN1 encoding */
    status = MAsn1Encode (pArray, pSerKey, serKeyLen, &serKeyLen);
    if (OK != status)
        goto exit;

    /* Use this new encoding to build a new key info */
    status = CRYPTO_makeKeyInfo (TRUE, (ubyte *) pAlgId, algIdLen, pSerKey, serKeyLen, ppSerializedKey, pSerializedKeyLen);

exit:

    if (NULL != pTapData && NULL != pTapData->pKey && !pTapData->isDeferUnload) /* should have already errored if NULL == pTapData->pKey, don't change status here */
    {
        status2 = TAP_unloadKey(pTapData->pKey, pErrContext);
        if (OK == status)
            status = status2;

        pTapData->isKeyLoaded = FALSE;
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_MEMSET_FREE(&pSerKey, serKeyLen);
    }

    if (NULL != serKey.pBuffer)
    {
        (void) TAP_UTILS_freeBuffer(&serKey);
    }

    if (NULL != pArray)
    {
        (void) MAsn1FreeElementArray (&pArray);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_deserializeSymKey(
    SymmetricKey **ppKey,
    ubyte *pSerializedKey,
    ubyte4 serializedKeyLen,
    void *pOpInfo
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED, index = 0;
    MocSymCtx pNewSymCtx = NULL;
    MocCtx pMocCtx = NULL;
    SymmetricKey *pNewKey = NULL;
    cryptoInterfaceSymAlgo algo;
    ubyte4 keyType = 0;
    byteBoolean match = 0;
    ubyte4 i = 0;

    MTapKeyData *pTapData = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;

    TAP_Key *pTapKey = NULL;
    TAP_Buffer serKey = {0};

    sbyte4 isPrivate = TRUE, cmpResult = -1;
    ubyte4 getAlgIdLen = 0, getKeyDataLen = 0, tapBlobLen = 0, bytesRead = 0;
    ubyte *pGetAlgId = NULL;
    ubyte *pGetKeyData = NULL;
    ubyte *pTapBlob = NULL;

    MAsn1Element *pArray = NULL;

    /* For the Symmetric TAP Key, the privateKeyData is defined as follows:
     * SEQ {
     *   Version version,
     *   ModuleId moduleId,
     *   TapPrivateKey tapPrivateKey
     * }
     *
     * where:
     * Version ::= INTEGER { v1(0) } (v1,...)
     * ModuleId ::= INTEGER { tpm2-1-2(1), tpm2-0(2) } (tpm-1-2, tpm-2-0, ...)
     * TapPrivateKey ::= OCTET STRING
     */
    MAsn1TypeAndCount pTemplate[4] =
    {
        { MASN1_TYPE_SEQUENCE, 3 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_OCTET_STRING, 0 }
    };

    if (NULL == ppKey || NULL == pSerializedKey)
        goto exit;

    /* Now parse the asn1, get the inner key info first */

    status = CRYPTO_findKeyInfoComponents ( pSerializedKey, serializedKeyLen, &pGetAlgId, &getAlgIdLen, &pGetKeyData, &getKeyDataLen, &isPrivate);
    if (OK != status)
        goto exit;

    /* Ensure alg id matches */
    for (i = 0; i < numAlgos; i++)
    {
        status = ASN1_compareOID (pSupportedAlgsInfo[i].pAlgId, pSupportedAlgsInfo[i].algIdLen, pGetAlgId, getAlgIdLen, NULL, &cmpResult);
        if (OK != status)
            goto exit;

        if (0 == cmpResult)
        {
            algo = pSupportedAlgsInfo[i].symAlgo;
            keyType = pSupportedAlgsInfo[i].keyType;
            match = TRUE;
            break;
        }
    }

    status = ERR_INVALID_INPUT;
    if (FALSE == match)
        goto exit;

    /* make sure we are enabled before continuing */
    status = CRYPTO_INTERFACE_checkTapSymAlgoStatus(algo, &algoStatus, &index);
    if (OK != status)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
        goto exit;

    status = MAsn1CreateElementArray (pTemplate, 4, MASN1_FNCT_DECODE, NULL, &pArray);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pGetKeyData, getKeyDataLen, pArray, &bytesRead);
    if (OK != status)
        goto exit;

    pTapBlob = pArray[3].value.pValue;
    tapBlobLen = pArray[3].valueLen;

    /* Deserialize the TAP key blob */
    serKey.pBuffer = pTapBlob;
    serKey.bufferLen = tapBlobLen;

    status = TAP_deserializeKey(&serKey, &pTapKey, pErrContext);
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(SymmetricKey));
    if (OK != status)
        goto exit;

    /* Now that we have a successfully deserialized TAP key, we'll go ahead and make the new contexts */
    status = CRYPTO_INTERFACE_getTapMocCtx(&pMocCtx);
    if (OK != status)
        goto exit;

    status = CRYPTO_getMocSymObjectFromIndex (index, pMocCtx, pOpInfo, &pNewSymCtx);
    if (OK != status)
        goto exit;

    /* First member of local data must be a MTapKeyData structure */
    pTapData = (MTapKeyData *) pNewSymCtx->pLocalData;
    if (NULL == pTapData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Also put the key in the local data */
    pTapData->pKey = pTapKey; pTapKey = NULL;

    /* Load the new MocSymCtx into the SymmetricKey */
    pNewSymCtx->state = CTX_STATE_CREATE;
    pNewKey->keyType = keyType;
    pNewKey->pKeyData = pNewSymCtx;
    pNewSymCtx = NULL;

    *ppKey = pNewKey;
    pNewKey = NULL;

exit:

    /* pGetKeyData, pGetAlgId, pTapBlob are not allocated, only set, so no need to free */
    if (NULL != pArray)
    {
        (void) MAsn1FreeElementArray (&pArray);
    }

    if (NULL != pTapKey)
    {
        (void) TAP_freeKey(&pTapKey);
    }

    if (NULL != pNewSymCtx)
    {
        (void) CRYPTO_freeMocSymCtx (&pNewSymCtx);
    }
    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymKeyLoadWithCreds(
    SymmetricKey *pKey,
    ubyte *pPassword, 
    ubyte4 passwordLen)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER, status2 = OK;
    MocSymCtx pSymCtx = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_CredentialList *pDummyCredList = NULL;
    TAP_CredentialList *pCredList = NULL;
    TAP_Credential *pCred = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    MTapKeyData *pTapData = NULL;

    if (NULL == pKey || NULL == pKey->pKeyData || NULL == pPassword)
    {
        goto exit;
    }

    if (!passwordLen)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    status = DIGI_CALLOC((void **) &pCredList, 1, sizeof(TAP_CredentialList));
    if (OK != status)
        goto exit;

    /* allocate the credential list */
    status = DIGI_CALLOC((void **) &pCredList->pCredentialList, 1, sizeof(TAP_Credential));
    if (OK != status)
        goto exit;

    pCredList->numCredentials = 1;

    pCred = pCredList->pCredentialList;
    
    status = DIGI_MALLOC((void **) &pCred->credentialData.pBuffer, passwordLen);
    if (OK != status)
        goto exit;

    pCred->credentialData.bufferLen = passwordLen;
    
    status = DIGI_MEMCPY(pCred->credentialData.pBuffer, pPassword, passwordLen);
    if (OK != status)
        goto exit;

    pCred->credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
    pCred->credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
    pCred->credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;

    pSymCtx = (MocSymCtx) pKey->pKeyData;
    /* pSymCtx already checked to not be NULL */

    pTapData = (MTapKeyData *) pSymCtx->pLocalData;
    if (NULL == pTapData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pTapKey = (TAP_Key *) pTapData->pKey;
    
    if (pTapData->isKeyLoaded)
    {
        status = TAP_unloadKey(pTapKey, pErrContext);
        if (OK != status)
            goto exit;
        
        pTapData->isKeyLoaded = FALSE;
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pDummyCredList,
                                                    (void *)pSymCtx, tap_key_load, 1/*get context*/)))
        {
            goto exit1;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pCredList, NULL, pErrContext);
    if (OK != status)
        goto exit1;

    pTapData->isKeyLoaded = TRUE;

exit1:

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pDummyCredList,
                                                    (void *)pSymCtx, tap_key_load, 0/* release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP Context release failed with status = ", status2);
        }
        if (OK == status)
            status = status2;
    }

exit:

    /* Free any internal structures */
    status2 = TAP_UTILS_clearCredentialList(pCredList);
    if (OK == status)
        status = status2;
    
    /* Free outer shell */
    status2 = DIGI_FREE((void** ) &pCredList);
    if (OK == status)
        status = status2;

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_deserializeSymKeyWithCreds(
    SymmetricKey **ppKey,
    ubyte *pSerializedKey,
    ubyte4 serializedKeyLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    void *pOpInfo
    )
{
    MSTATUS status = OK;
    SymmetricKey *pNewKey = NULL;

    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pNewKey, pSerializedKey, serializedKeyLen, pOpInfo);
    if (OK != status)
        goto exit;
    
    status = CRYPTO_INTERFACE_TAP_SymKeyLoadWithCreds(pNewKey, pPassword, passwordLen);
    if (OK != status)
        goto exit;

    *ppKey = pNewKey; pNewKey = NULL;

exit: 

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pNewKey);
    }
   
    return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_deleteSymKey(
    SymmetricKey **ppKey
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER, fStatus = OK;

    if (NULL == ppKey)
        goto exit;

    status = OK;
    if (NULL == *ppKey)
        goto exit;  /* ok no-op */

    /* Free the inner MocSymCtx */
    if (NULL != (*ppKey)->pKeyData)
    {
       status = CRYPTO_freeMocSymCtx((MocSymCtx *) &((*ppKey)->pKeyData));
    }

    /* free the outer shell */
    fStatus = DIGI_FREE((void **) ppKey);
    if (OK == status)
        status = fStatus;

exit:

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_SymImportExternalKey(
    SymmetricKey **ppNewKey,
    void *pOpInfo,
    void *pArgs
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED, index = 0;
    MocSymCtx pNewSymCtx = NULL;
    SymmetricKey *pNewKey = NULL;
    MocCtx pMocCtx = NULL;
    ubyte4 keyType = 0;
    ubyte4 token = 0;
    MSymOperator operator = MAesTapOperator;
    cryptoInterfaceSymAlgo symAlgo = moc_alg_aes;
    MTapKeyData *pTapData = NULL;
    TAP_AttributeList createAttributes = {0};
    TAP_Buffer keyData = {0};
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrCtx = &errContext;
    MSymTapCreateArgs *pCreateArgs = (MSymTapCreateArgs *) pArgs;

    if ( (NULL == pCreateArgs) || (NULL == pCreateArgs->pKeyData) || (NULL == pCreateArgs->pKeyInfo) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (pCreateArgs->pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:

            /* operator and symAlgo arleady are MAesTapOperator and moc_alg_aes by default */

            switch (pCreateArgs->pKeyInfo->algKeyInfo.aesInfo.symMode)
            {
                case TAP_SYM_KEY_MODE_CTR:
                    keyType = MOC_SYM_ALG_AES_CTR;
                    break;

                case TAP_SYM_KEY_MODE_OFB:
                    keyType = MOC_SYM_ALG_AES_OFB;
                    break;

                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_AES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_CFB:
                    keyType = MOC_SYM_ALG_AES_CFB;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_AES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_GCM:
                    keyType = MOC_SYM_ALG_AES_GCM;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_AES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_AES;
                    break;
            }
            break;

        case TAP_KEY_ALGORITHM_DES:

            operator = MDesTapOperator;
            symAlgo = moc_alg_des;

            switch (pCreateArgs->pKeyInfo->algKeyInfo.desInfo.symMode)
            {
                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_DES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_DES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_DES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_DES;
                    break;
            }
            break;

        case TAP_KEY_ALGORITHM_TDES:

            operator = MTDesTapOperator;
            symAlgo = moc_alg_tdes;

            switch (pCreateArgs->pKeyInfo->algKeyInfo.tdesInfo.symMode)
            {
                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_TDES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_TDES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_TDES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_TDES;
                    break;
            }
            break;

        case TAP_KEY_ALGORITHM_HMAC:

            operator = MHmacTapOperator;
            symAlgo = moc_alg_hmac;
            keyType = MOC_SYM_ALG_HMAC;
            break;

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    status = CRYPTO_INTERFACE_checkTapSymAlgoStatus(symAlgo, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
        goto exit;
    }

    /* Get a reference to the Tap MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getTapMocCtx(&pMocCtx);
    if (OK != status)
        goto exit;

    status = CRYPTO_createMocSymCtx(operator, pOpInfo, pMocCtx, &pNewSymCtx);
    if (OK != status)
        goto exit;

    pTapData = (MTapKeyData *)pNewSymCtx->pLocalData;
    if (NULL == pTapData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    token = (ubyte4)pCreateArgs->token;
    keyData.pBuffer = pCreateArgs->pKeyData;
    keyData.bufferLen = pCreateArgs->keyDataLen;

    status = DIGI_MALLOC((void **) &createAttributes.pAttributeList, 2 * sizeof(TAP_Attribute));
        if (OK != status)
            goto exit;

    createAttributes.pAttributeList[0].type = TAP_ATTR_TOKEN_OBJECT;
    createAttributes.pAttributeList[0].length = sizeof(token);
    createAttributes.pAttributeList[0].pStructOfType = (void *)&token;

    createAttributes.pAttributeList[1].type = TAP_ATTR_OBJECT_VALUE;
    createAttributes.pAttributeList[1].length = sizeof(keyData);
    createAttributes.pAttributeList[1].pStructOfType = &keyData;
    createAttributes.listLen = 2;

    status = TAP_symImportExternalKey (
        pTapData->pTapCtx, pTapData->pEntityCredentials, pCreateArgs->pKeyInfo, &createAttributes,
        pTapData->pKeyCredentials, &(pTapData->pKey), pErrCtx);
    if (OK != status)
        goto exit;

    pTapData->isKeyLoaded = TRUE;
    
    status = DIGI_CALLOC((void **)&pNewKey, 1, sizeof(SymmetricKey));
    if (OK != status)
        goto exit;

    /* Load the MocSymCtx into the SymmetricKey wrapper */
    pNewKey->pKeyData = (void *) pNewSymCtx; pNewSymCtx = NULL;
    pNewKey->keyType = keyType;

    /* Give caller ownership of new SymmetricKey */
    *ppNewKey = pNewKey; pNewKey = NULL;

exit:

    if (NULL != pNewKey)
    {
        (void) DIGI_FREE((void **)&pNewKey);
    }
    if (NULL != pNewSymCtx)
    {
        (void) CRYPTO_freeMocSymCtx (&pNewSymCtx);
    }
    if (NULL != createAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &createAttributes.pAttributeList);
    }
    
    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_symGetTapObjectId(SymmetricKey *pKey, ubyte **ppId, ubyte4 *pIdLen)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status;
    MocSymCtx pMocSymCtx = NULL;
    MTapKeyData *pLocalData = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_ObjectAttributes *pObjAttributes = NULL;
    ubyte4 i = 0;
    ubyte found = FALSE;

    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == pKey->pKeyData) || (NULL == ppId) || (NULL == pIdLen) )
    {
        goto exit;
    }

    pMocSymCtx = (MocSymCtx)pKey->pKeyData;
    pLocalData = (MTapKeyData *)pMocSymCtx->pLocalData;

    if (NULL == pLocalData)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pTapKey = pLocalData->pKey;

    if (NULL == pTapKey)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pObjAttributes = &(pTapKey->providerObjectData.objectInfo.objectAttributes);
    if (NULL == pObjAttributes)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    for (i = 0; i < pObjAttributes->listLen; i++)
    {
        if (TAP_ATTR_OBJECT_ID_BYTESTRING == pObjAttributes->pAttributeList[i].type)
        {
            if (NULL == pObjAttributes->pAttributeList[i].pStructOfType)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            status = DIGI_MALLOC_MEMCPY (
                (void **)ppId, 
                ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->bufferLen,
                ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->pBuffer,
                ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->bufferLen);
            if (OK != status)
                goto exit;

            *pIdLen = ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->bufferLen;
            found = TRUE;
            break;
        }
    }

    if (FALSE == found)
    {
        status = ERR_NOT_FOUND;
    }

exit:
    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}
