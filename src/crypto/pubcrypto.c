/*
 * pubcrypto.c
 *
 * General Public Crypto Operations
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


/*------------------------------------------------------------------*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PUBCRYPTO_INTERNAL__

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/memory_debug.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../asn1/parseasn1.h"
#include "../asn1/mocasn1.h"
#include "../asn1/derencoder.h"
#include "../asn1/oiddefs.h"
#include "../common/base64.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../crypto/dsa.h"
#endif
#include "../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/ecc.h"
#include "../crypto/primeec_priv.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../common/serialcommon.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/sec_key.h"
#include "../crypto/crypto.h"
#include "../crypto/malgo_id.h"
#include "../crypto/pkcs_key.h"
#include "../crypto/mocasymkeys/mocsw/commonrsa.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_pubcrypto_priv.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#include "../crypto_interface/cryptointerface.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "../crypto_interface/crypto_interface_tap.h"
#endif

#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs.h"
#endif
#endif

#if (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__) && defined(__ENABLE_DIGICERT_TPM__))
#include "../crypto/secmod.h"
#include "../smp/smp_tpm12/tpm12_lib/hsmrsainfo.h"
#endif

#ifndef __DISABLE_DIGICERT_RSA__
#define __DIGICERT_ALG_RSA__ 1
#else
#define __DIGICERT_ALG_RSA__ 0
#endif

#ifdef __ENABLE_DIGICERT_DSA__
#define __DIGICERT_ALG_DSA__ 1
#else
#define __DIGICERT_ALG_DSA__ 0
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#define __DIGICERT_ALG_ECC__ 1
#else
#define __DIGICERT_ALG_ECC__ 0
#endif

#ifdef __ENABLE_DIGICERT_PQC__
#ifdef __ENABLE_DIGICERT_ECC__
#define __DIGICERT_ALG_QS__ 2
#else
#define __DIGICERT_ALG_QS__ 1
#endif /* __ENABLE_DIGICERT_ECC__ */
#else
#define __DIGICERT_ALG_QS__ 0
#endif /* __ENABLE_DIGICERT_PQC__ */

#define MOCANA_ALG_COUNT (__DIGICERT_ALG_RSA__ + __DIGICERT_ALG_DSA__ + __DIGICERT_ALG_ECC__ + __DIGICERT_ALG_QS__)

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_initAsymmetricKey(AsymmetricKey* pKey)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    status = DIGI_MEMSET((ubyte *)pKey, 0x00, sizeof(AsymmetricKey));
    pKey->type = akt_undefined;

exit:
    return status;
}

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
extern MSTATUS
CRYPTO_createDSAKey( AsymmetricKey* pKey, vlong** ppVlongQueue)
{
    MSTATUS status;

    if (!pKey)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = CRYPTO_uninitAsymmetricKey(pKey, ppVlongQueue)))
        goto exit;

    if (OK > (status = DSA_createKey(&pKey->key.pDSA)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pKey->key.pDSA);

    pKey->type = akt_dsa;

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
extern MSTATUS
CRYPTO_createRSAKey( AsymmetricKey* pKey, vlong** ppVlongQueue)
{
    MSTATUS status;

    if (!pKey)
    {
        return ERR_NULL_POINTER;
    }
    if (OK > ( status = CRYPTO_uninitAsymmetricKey( pKey, ppVlongQueue)))
        goto exit;

    if (OK > (status = RSA_createKey( &pKey->key.pRSA)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pKey->key.pRSA);

    pKey->type = akt_rsa;
exit:
    return status;
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
extern MSTATUS
CRYPTO_createECCKeyEx(
    AsymmetricKey* pKey,
    ubyte4 curveId
    )
{
    MSTATUS status;

    if (NULL == pKey)
        return ERR_NULL_POINTER;

    if (OK > (status = CRYPTO_uninitAsymmetricKey(pKey, NULL)))
        goto exit;

    if (OK > (status = CRYPTO_INTERFACE_EC_newKeyAux (curveId, &(pKey->key.pECC))))
        goto exit;

    DEBUG_RELABEL_MEMORY(pKey->key.pECC);

    pKey->type = akt_ecc;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    if (cid_EC_Ed25519 == curveId || cid_EC_Ed448 == curveId)
        pKey->type = akt_ecc_ed;
#endif

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
extern MSTATUS
CRYPTO_createECCKey( AsymmetricKey* pKey, PEllipticCurvePtr pEC)
{
    MSTATUS status;

    if (!pKey)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = CRYPTO_uninitAsymmetricKey( pKey, 0)))
    {
        goto exit;
    }

    if (OK > (status = EC_newKey( pEC, &pKey->key.pECC)))
    {
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pKey->key.pECC);

    pKey->type = akt_ecc;
exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

#endif /* if (defined(__ENABLE_DIGICERT_ECC__))*/

/*------------------------------------------------------------------*/

extern MSTATUS
CRYPTO_copyAsymmetricKey(AsymmetricKey* pNew, const AsymmetricKey* pSrc)
{
    MSTATUS status;
    hwAccelDescr hwAccelCtx;

    CRYPTO_uninitAsymmetricKey( pNew, 0);

    /* If we're copying pSrc, and it is NULL or if it is empty, we don't return
     * an error, we just want the copy to be empty (which just happened in the
     * previous line of code).
     */
    status = OK;
    if (NULL == pSrc)
      goto exit;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    pNew->type = pSrc->type;

    switch (pSrc->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
        case akt_tap_rsa:
        {
            status = RSA_cloneKey(MOC_RSA(hwAccelCtx) &pNew->key.pRSA, pSrc->key.pRSA, 0);
            break;
        }
#endif /* __DISABLE_DIGICERT_RSA__ */
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        case akt_ecc_ed:
        case akt_tap_ecc:
        {
            status = EC_cloneKeyEx(MOC_ECC(hwAccelCtx) &pNew->key.pECC, pSrc->key.pECC);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
        {
            status = DSA_cloneKey(MOC_DSA(hwAccelCtx) &pNew->key.pDSA, pSrc->key.pDSA);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
        case akt_custom:
        case akt_moc:
        {
          pNew->key = pSrc->key;
          status = OK;
          break;
        }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_hybrid:

            pNew->clAlg = pSrc->clAlg;
            if (pSrc->clAlg < cid_RSA_2048_PKCS15) /* ECC */
            {
                status = EC_cloneKeyEx(MOC_ECC(hwAccelCtx) &pNew->key.pECC, pSrc->key.pECC);
            }
            else /* RSA */
            {
                status = RSA_cloneKey(MOC_RSA(hwAccelCtx) &pNew->key.pRSA, pSrc->key.pRSA, 0);
            }
            if (OK != status)
                goto exit;
        
        /* fallthrough */
        case akt_qs:
            status = CRYPTO_INTERFACE_QS_cloneCtx(&pNew->pQsCtx, pSrc->pQsCtx);
            break;
#endif

        case akt_undefined:
        {
            status = OK;
            break;
        }
        default:
        {
            status = ERR_INTERNAL_ERROR;
            break;
        }
    }

    if ( NULL != pSrc->pAlgoId)
    {
        status = ALG_ID_copy(pSrc->pAlgoId, &(pNew->pAlgoId));
        if (OK != status)
        {
            goto exit;
        }
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
CRYPTO_uninitAsymmetricKey(AsymmetricKey* pKey, vlong** ppVlongQueue)
{
    MSTATUS status, fstatus;

    if (!pKey)
    {
        return ERR_NULL_POINTER;
    }
    switch (pKey->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
        case akt_rsa_pss:
        case akt_tap_rsa:
        {
            status = RSA_freeKey( &pKey->key.pRSA, ppVlongQueue);
            break;
        }
#endif /* __DISABLE_DIGICERT_RSA__ */
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        case akt_ecc_ed:
        case akt_tap_ecc:
        {
            status = EC_deleteKeyEx( &pKey->key.pECC);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
        {
            status = DSA_freeKey(&pKey->key.pDSA, ppVlongQueue);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
        case akt_custom:
        case akt_moc:
        {
          status = CRYPTO_freeMocAsymKey (&(pKey->key.pMocAsymKey), ppVlongQueue);
          break;
        }
#endif
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
        case akt_hsm_rsa:
        {
          status = HSMRSAINFO_freeHSMRSAInfo (&(pKey->key.pRSA->hsmInfo));
          pKey->key.pRSA->hsmInfo = NULL;
          if (OK == status)
          {
            status = RSA_freeKey( &pKey->key.pRSA, ppVlongQueue);
          }
          break;
        }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_hybrid:
        {
            if (pKey->clAlg < cid_RSA_2048_PKCS15) /* ECC */
            {
                status = EC_deleteKeyEx(&pKey->key.pECC);
            }
            else /* RSA */
            {
                status = RSA_freeKey( &pKey->key.pRSA, ppVlongQueue);
            }
            fstatus = CRYPTO_INTERFACE_QS_deleteCtx(&pKey->pQsCtx);
            if (OK == status)
                status = fstatus;

            pKey->clAlg = 0;
            break;
        }
        case akt_qs:
        {
            status = CRYPTO_INTERFACE_QS_deleteCtx(&pKey->pQsCtx);
            break;
        }
#endif
        case akt_undefined:
        {
            status = OK;
            break;
        }
        default:
        {
            status = ERR_INTERNAL_ERROR;
            break;
        }
    }

    if (NULL != pKey->pAlgoId)
    {
        fstatus = ALG_ID_free(&(pKey->pAlgoId));
        if (OK == status)
            status = fstatus;
    }

    if (OK > status)
        goto exit;

    pKey->type = akt_undefined;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CRYPTO_matchPublicKey(const AsymmetricKey* pKey1, const AsymmetricKey* pKey2)
{
    byteBoolean res = 0;
    MSTATUS status;
    hwAccelDescr hwAccelCtx;
#if defined(__ENABLE_DIGICERT_TAP__)
    AsymmetricKey pubKey1 = {0};
    AsymmetricKey pubKey2 = {0};
#endif

    /* see if the public key part of the keys match */
    if (!pKey1 || !pKey2)
        return ERR_NULL_POINTER;

    if ((pKey1->type & 0xFF) != (pKey2->type & 0xFF))
        return ERR_FALSE;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

#if defined(__ENABLE_DIGICERT_TAP__)
    if (0 != (pKey1->type & 0xFF0000))
    {
        status = CRYPTO_INTERFACE_getPublicKey(
            (AsymmetricKey *) pKey1, &pubKey1);
        if (OK != status)
        {
            goto exit;
        }

        pKey1 = &pubKey1;
    }

    if (0 != (pKey2->type & 0xFF0000))
    {
        status = CRYPTO_INTERFACE_getPublicKey(
            (AsymmetricKey *) pKey2, &pubKey2);
        if (OK != status)
        {
            goto exit;
        }

        pKey2 = &pubKey2;
    }
#endif

    switch (pKey1->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
    case akt_rsa:
        if (OK > (status = RSA_equalKey(MOC_RSA(hwAccelCtx) pKey1->key.pRSA, pKey2->key.pRSA, &res)))
            goto exit;
        break;
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
    case akt_ecc:
    case akt_ecc_ed:
        if (OK > (status = EC_equalKeyEx(MOC_ECC(hwAccelCtx) pKey1->key.pECC, pKey2->key.pECC, &res)))
            goto exit;
        break;
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
    case akt_dsa:
        if (OK > (status = DSA_equalKey(MOC_DSA(hwAccelCtx) pKey1->key.pDSA, pKey2->key.pDSA, &res)))
            goto exit;
        break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case akt_hybrid:

        if (pKey1->clAlg != pKey2->clAlg)
        {
            res = FALSE;
            goto exit;
        }
        
        if (pKey1->clAlg < cid_RSA_2048_PKCS15) /* ECC */
        {
            if (OK > (status = EC_equalKeyEx(MOC_ECC(hwAccelCtx) pKey1->key.pECC, pKey2->key.pECC, &res)))
                goto exit;
        }
        else /* RSA */
        {
            if (OK > (status = RSA_equalKey(MOC_RSA(hwAccelCtx) pKey1->key.pRSA, pKey2->key.pRSA, &res)))
                goto exit;
        }
        if (FALSE == res)
            goto exit;
          
        /* fallthrough */
    case akt_qs: 
        if (OK > (status = CRYPTO_INTERFACE_QS_equalKey(pKey1->pQsCtx, pKey2->pQsCtx, MOC_ASYM_KEY_TYPE_PUBLIC, &res)))
            goto exit;
        
        break;
#endif
      default:
          break;

    }

exit:

#if defined(__ENABLE_DIGICERT_TAP__)
    CRYPTO_uninitAsymmetricKey(&pubKey2, NULL);
    CRYPTO_uninitAsymmetricKey(&pubKey1, NULL);
#endif

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if (OK == status)
        return (res) ? OK : ERR_FALSE;
    return ERR_INVALID_ARG;
}


/*------------------------------------------------------------------*/


extern MSTATUS CRYPTO_loadAlgoId (
  AsymmetricKey *pAsymKey,
  void **ppAlgoId
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pAsymKey) || (NULL == ppAlgoId) )
    goto exit;

  if (NULL == *ppAlgoId)
    goto exit;

  if (NULL != pAsymKey->pAlgoId)
  {
    status = ALG_ID_free(&(pAsymKey->pAlgoId));
    if (OK != status)
      goto exit;
  }

  status = OK;
  pAsymKey->pAlgoId = *ppAlgoId;

  /* If we reach this point, everything worked, so NULL out the AlgoId.
   */
  *ppAlgoId = NULL;

exit:

  return (status);
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

extern MSTATUS CRYPTO_serializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey  *pKeyToSerialize,
  MKeySerialize *pSupportedAlgorithms,
  ubyte4 supportedAlgorithmCount,
  serializedKeyFormat format,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status;
  ubyte4 index;
  MSerializeInfo serialInfo = {
    .ppSerializedKey = ppSerializedKey,
    .pSerializedKeyLen = pSerializedKeyLen,
    .derLen = 0, .headerLen = 0, .footerLen = 0,
    .formatToUse = format,
    .pDerEncoding = NULL, .pHeader = NULL, .pFooter = NULL,
    .pPubHeader = MOC_PUB_PEM_HEADER,
    .pPubFooter = MOC_PUB_PEM_FOOTER,
    .pPriHeader = MOC_PRI_PEM_HEADER,
    .pPriFooter = MOC_PRI_PEM_FOOTER,
    .dataToReturn = {0}
  };

  status = ERR_NULL_POINTER;
  if (NULL == pSupportedAlgorithms)
    goto exit;

  /* Execute initialization code common to all serialization routines */
  status = SerializeCommonInit(&serialInfo, format);
    if (OK != status)
      goto exit;

    /* If the key is not MocAsym, call each of the MKeySerialize.
     */
    for (index = 0; index < supportedAlgorithmCount; ++index)
    {
      /* If this succeeds, break out of the loop.
       */
      status = pSupportedAlgorithms[index] ( MOC_ASYM(hwAccelCtx)
      pKeyToSerialize, serialInfo.formatToUse, serialInfo.dataToReturn.ppData,
      serialInfo.dataToReturn.pLength);
      if (OK == status)
        break;
    }
    /* If we broke out of the loop early, we found a result.
     * If not, error.
     */
    status = ERR_UNKNOWN_DATA;
    if (index >= supportedAlgorithmCount)
      goto exit;

  /* At this point we have an encoding. If therequested result is not PEM, we're
   * done. If formatToUse is the same as format, it's not PEM.
   */
  status = OK;
  if (serialInfo.formatToUse == format)
    goto exit;

  /* Wrap encoding into PEM format, common to all serialization routines */
  status = SerializeCommon(&serialInfo);

exit:

  if (NULL != serialInfo.pDerEncoding)
  {
    DIGI_FREE ((void **)&(serialInfo.pDerEncoding));
  }

  return (status);
}

extern MSTATUS CRYPTO_deserializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MKeySerialize *pSupportedAlgorithms,
  ubyte4 supportedAlgorithmCount,
  AsymmetricKey *pDeserializedKey
  )
{
  MSTATUS status;
  ubyte4 index, keyDerLen;
  ubyte *pKeyDer = NULL;
  MKeyOperatorData keyData;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSerializedKey) || (NULL == pDeserializedKey) ||
       (NULL == pSupportedAlgorithms) || (0 == supportedAlgorithmCount) )
    goto exit;

  /* Check the first byte of the serialized key. If it is '-', it is PEM. If it
   * is 00, it is a key blob. If it is 0x30, it is the DER encoding.
   */
  keyData.pData = pSerializedKey;
  keyData.length = serializedKeyLen;
  if ('-' == pSerializedKey[0])
  {
    /* If this is PEM, call the function that decodes these types of structures.
     */
#if (defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__))     /* added as CA_MGMT_decodeCertificate function defination is also part fo same flags*/
    status = CA_MGMT_decodeCertificate (
      pSerializedKey, serializedKeyLen, &pKeyDer, &keyDerLen);
#endif
    if (OK != status)
      goto exit;

    keyData.pData = pKeyDer;
    keyData.length = keyDerLen;
  }


#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
  if ( (akt_moc == pDeserializedKey->type) ||
       (akt_tap_rsa == pDeserializedKey->type) ||
       (akt_tap_ecc == pDeserializedKey->type) ||
       (akt_custom == pDeserializedKey->type) )
  {
    /* If the input key was already a MocAsymKey, then just have it deserialize
     * itself.
     * If the key is a MocAsymKey already, we don't try the lists of functions, so
     * whether this call works or not, we're done, just exit.
     */
    status = ERR_INVALID_INPUT;
    if (NULL == pDeserializedKey->key.pMocAsymKey)
      goto exit;

    if (NULL == pDeserializedKey->key.pMocAsymKey->KeyOperator)
      goto exit;

    status = pDeserializedKey->key.pMocAsymKey->KeyOperator (
      pDeserializedKey->key.pMocAsymKey, NULL, MOC_ASYM_OP_DESERIALIZE, (void *)&keyData,
      NULL, NULL);
    goto exit;
  }
#endif

  /* The key object passed in was not a MocAsymKey. So try all the
   * MKeySerialize.
   */
  for (index = 0; index < supportedAlgorithmCount; ++index)
  {
    /* If this succeeds, break out of the loop.
     */
    status = pSupportedAlgorithms[index] ( MOC_ASYM(hwAccelCtx)
      pDeserializedKey, deserialize, &(keyData.pData), &(keyData.length));
    if (OK == status)
      break;
  }

exit:

  if (NULL != pKeyDer)
  {
    DIGI_FREE ((void **)&pKeyDer);
  }

  return (status);
}

extern MSTATUS CRYPTO_serializeAsymKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pKeyToSerialize,
  serializedKeyFormat format,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
  MocAsymKey pKeyToUse = NULL;
#endif
  ubyte4 supportedAlgorithmCount = MOCANA_ALG_COUNT;
  MKeySerialize pSupportedAlgorithms[MOCANA_ALG_COUNT] = {
#if (!defined(__DISABLE_DIGICERT_RSA__))
    KeySerializeRsa,
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
    KeySerializeDsa,
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    KeySerializeEcc,
#if (defined(__ENABLE_DIGICERT_PQC__))
    KeySerializeHybrid,
    KeySerializeQs
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
  };

  status = ERR_NULL_POINTER;
  if (NULL == pKeyToSerialize)
    goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
  if (akt_tap_rsa == pKeyToSerialize->type)
  {
    if ( (NULL != pKeyToSerialize->key.pRSA->pPrivateKey) &&
         (NULL != pKeyToSerialize->key.pRSA->pPrivateKey->pKeyData) )
    {
      pKeyToUse = pKeyToSerialize->key.pRSA->pPrivateKey;
    }
    else
    {
      pKeyToUse = pKeyToSerialize->key.pRSA->pPublicKey;
    }

    status = CRYPTO_serializeMocAsymKeyAlloc (
      pKeyToUse, format, ppSerializedKey, pSerializedKeyLen);
  }
#ifdef __ENABLE_DIGICERT_ECC__
  else if (akt_tap_ecc == pKeyToSerialize->type)
  {
    if ( (NULL != pKeyToSerialize->key.pECC->pPrivateKey) &&
         (NULL != pKeyToSerialize->key.pECC->pPrivateKey->pKeyData) )
    {
      pKeyToUse = pKeyToSerialize->key.pECC->pPrivateKey;
    }
    else
    {
      pKeyToUse = pKeyToSerialize->key.pECC->pPublicKey;
    }

    status = CRYPTO_serializeMocAsymKeyAlloc (
      pKeyToUse, format, ppSerializedKey, pSerializedKeyLen);
  }
#endif /* __ENABLE_DIGICERT_ECC__ */
  else
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
  {
    status = CRYPTO_serializeKey ( MOC_ASYM(hwAccelCtx)
      pKeyToSerialize, pSupportedAlgorithms, supportedAlgorithmCount, format,
      ppSerializedKey, pSerializedKeyLen);
  }

exit:
  return status;
}

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)

extern MSTATUS CRYPTO_getKeyTapInfo(
  ubyte *pKey,
  ubyte4 keyLen,
  MocCtx pMocCtx,
  byteBoolean *pIsTap,
  ubyte4 *pProvider,
  ubyte4 *pModuleId
)
{
  MSTATUS status = ERR_NULL_POINTER;
  MocAsymKey pNewKey = NULL;

  if (NULL == pKey || NULL == pIsTap || NULL == pProvider || NULL == pModuleId)
    goto exit;
      
  *pIsTap = FALSE;

  /* First see if its a standard TAP key, note deserialize won't trigger
     the callback function but will allow us to obtain the provider and module */
  status = CRYPTO_deserializeMocAsymKey (pKey, keyLen, pMocCtx, &pNewKey, NULL);
  if (OK == status)
  {
    status = CRYPTO_INTERFACE_TAP_getKeyTapInfo(pNewKey, pProvider, pModuleId);
    if (OK != status)
      goto exit;

    *pIsTap = TRUE;   
  }
  else /* See if it is a secure storage key */
  {
    ubyte *pKeyDer = NULL;
    ubyte4 keyDerLen = 0;

    MKeyOperatorData inputInfo = {0};
    MKeyObjectInfo tapInfo = {0};
  
    /* check if it's PEM first */
    if ('-' == pKey[0])
    {
#if (defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__))
      status = CA_MGMT_decodeCertificate (
        pKey, keyLen, &pKeyDer, &keyDerLen);
      if (OK != status)
        goto exit;

      inputInfo.pData = pKeyDer;
      inputInfo.length = keyDerLen;
#else
      status = ERR_NOT_IMPLEMENTED;
      goto exit;
#endif
    }
    else
    {
      inputInfo.pData = pKey;
      inputInfo.length = keyLen;
    }

    /* Call the operator directly */
    status = KeyOperatorSSTap (NULL, NULL, MOC_ASYM_OP_GET_PARAMS, &inputInfo, &tapInfo, NULL);

    /* Regardless of status free der key if needbe */
    if (NULL != pKeyDer)
    {
      (void) DIGI_MEMSET_FREE(&pKeyDer, keyDerLen);
    }

    if (OK == status)
    {
      *pIsTap = TRUE;
      *pProvider = tapInfo.provider;
      *pModuleId = tapInfo.moduleId;
    }
    else
    {
      /* correctly determined it's not a TAP Key, return OK */
      status = OK;
    }
  }

exit:
  
  if (NULL != pNewKey)
  {
    (void) CRYPTO_freeMocAsymKey(&pNewKey, NULL);
  }  

  return status;
}

extern MSTATUS CRYPTO_serializeAsymKeyToStorage(
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pKeyToSerialize,
  serializedKeyFormat format,
  ubyte *pId,
  ubyte4 idLen,
  ubyte4 tokenId,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
)
{
  MSTATUS status = ERR_NULL_POINTER;

  MKeyOperatorData inputInfo = {0};
  MKeyOperatorDataReturn outputInfo = {0};
  MKeyObjectInfo objInfo = {0}; 

  serializedKeyFormat innerFormat = format; /* default */
  ubyte *pInnerKey = NULL;
  ubyte4 innerKeyLen = 0;

  MSerializeInfo serialInfo = {
    .ppSerializedKey = ppSerializedKey,
    .pSerializedKeyLen = pSerializedKeyLen,
    .derLen = 0, .headerLen = 0, .footerLen = 0,
    .formatToUse = format,
    .pDerEncoding = NULL, .pHeader = NULL, .pFooter = NULL,
    .pPubHeader = MOC_PUB_PEM_HEADER,
    .pPubFooter = MOC_PUB_PEM_FOOTER,
    .pPriHeader = MOC_PRI_PEM_HEADER,
    .pPriFooter = MOC_PRI_PEM_FOOTER,
    .dataToReturn = {0}
  };

  if (NULL == pKeyToSerialize || NULL == pId || NULL == ppSerializedKey || NULL == pSerializedKeyLen)
    goto exit;

  status = ERR_INVALID_ARG;
  if (noFormat == format || mocanaBlobVersion2 == format || deserialize == format)
    goto exit;

  /* Execute initialization code common to all serialization routines */
  status = SerializeCommonInit(&serialInfo, format);
  if (OK != status)
    goto exit;

  /* We'll change PEM TO DER form for inner key */
  if (publicKeyPem == format)
    innerFormat = publicKeyInfoDer;
  else if (privateKeyPem == format)
    innerFormat = privateKeyInfoDer;

  status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyToSerialize, innerFormat, &pInnerKey, &innerKeyLen);
  if (OK != status)
    goto exit;

  inputInfo.pData = pInnerKey;
  inputInfo.length = innerKeyLen;
  inputInfo.pAdditionalOpInfo = (void *) &objInfo;

  objInfo.pId = pId;
  objInfo.idLen = idLen;
  objInfo.tokenId = tokenId;

  outputInfo.ppData = serialInfo.dataToReturn.ppData;
  outputInfo.pLength = serialInfo.dataToReturn.pLength;

  /* Call the operator directly */
  status = KeyOperatorSSTap (NULL, NULL, MOC_ASYM_OP_SERIALIZE, &inputInfo, &outputInfo, NULL);
  if (OK != status)
    goto exit;

  /* if we wanted DER form then we are done, otherwise */
  if (publicKeyPem == format || privateKeyPem == format)
  {
    status = SerializeCommon(&serialInfo);
  }

exit:

  if (NULL != pInnerKey)
  {
    (void) DIGI_MEMSET_FREE (&pInnerKey, innerKeyLen);
  }

  if (NULL != serialInfo.pDerEncoding)
  {
    (void) DIGI_MEMSET_FREE (&serialInfo.pDerEncoding, serialInfo.derLen);
  }

  return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

extern MSTATUS CRYPTO_deserializeAsymKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MocCtx pMocCtx,
  AsymmetricKey *pDeserializedKey
  )
{
  MSTATUS status;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
  MocAsymKey pNewKey = NULL;
  ubyte4 algoFlag = 0;
  ubyte4 keyType = 0;
#endif
  ubyte4 supportedAlgorithmCount = MOCANA_ALG_COUNT;
  MKeySerialize pSupportedAlgorithms[MOCANA_ALG_COUNT] = {
#if (defined(__ENABLE_DIGICERT_DSA__))
    KeySerializeDsa,
#endif
#if (!defined(__DISABLE_DIGICERT_RSA__))
    KeySerializeRsa,
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    KeySerializeEcc,
#if (defined(__ENABLE_DIGICERT_PQC__))
    KeySerializeHybrid,
    KeySerializeQs
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
  };

  /* First attempt to have any loaded TAP operators deserialize this key blob */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
  status = CRYPTO_deserializeMocAsymKey (
    pSerializedKey, serializedKeyLen, pMocCtx, &pNewKey, NULL);
  if (OK == status)
  {
    /* We were able to deserialize the key successfully, now determine the
     * key type and load it into the AsymmetricKey */
    algoFlag = pNewKey->localType & MOC_LOCAL_TYPE_HW_MASK;

    /* Is this a TAP key? */
    status = ERR_BAD_KEY_TYPE;
    if (0 != (algoFlag & MOC_LOCAL_TYPE_TAP))
    {
      algoFlag = (pNewKey->localType & MOC_LOCAL_TYPE_COM_MASK) |
                (pNewKey->localType & MOC_LOCAL_TYPE_ALG_MASK);

      switch(algoFlag)
      {
        case MOC_ASYM_ALG_RSA:
          keyType = akt_tap_rsa;
          break;

        case MOC_LOCAL_KEY_ECC:
        case MOC_ASYM_ALG_ECC_P192:
        case MOC_ASYM_ALG_ECC_P224:
        case MOC_ASYM_ALG_ECC_P256:
        case MOC_ASYM_ALG_ECC_P384:
        case MOC_ASYM_ALG_ECC_P521:
          keyType = akt_tap_ecc;
          break;

        default:
          goto exit;
      }
    }

    status = CRYPTO_INTERFACE_loadAsymmetricKey (
      pDeserializedKey, keyType, (void **)&pNewKey);
  }
#ifdef __ENABLE_DIGICERT_TAP__  
  else
  {
    ubyte *pInnerKey = NULL;
    ubyte4 innerKeyLen = 0;
    ubyte *pKeyDer = NULL;
    ubyte4 keyDerLen = 0;

    MKeyOperatorData inputInfo = {0};
    MKeyOperatorDataReturn outputInfo = {0};

    /* check if it's PEM first */
    if ('-' == pSerializedKey[0])
    {
#if (defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__))
      status = CA_MGMT_decodeCertificate (
        pSerializedKey, serializedKeyLen, &pKeyDer, &keyDerLen);
      if (OK != status)
        goto exit;

      inputInfo.pData = pKeyDer;
      inputInfo.length = keyDerLen;
#else
      status = ERR_NOT_IMPLEMENTED;
      goto exit;
#endif
    }
    else
    {
      inputInfo.pData = pSerializedKey;
      inputInfo.length = serializedKeyLen;
    }

    outputInfo.ppData = &pInnerKey;
    outputInfo.pLength = &innerKeyLen;

    /* Call the operator directly */
    status = KeyOperatorSSTap (NULL, pMocCtx, MOC_ASYM_OP_DESERIALIZE, &inputInfo, &outputInfo, NULL);
    
    /* Regardless of status free der key if needbe */
    if (NULL != pKeyDer)
    {
      (void) DIGI_MEMSET_FREE(&pKeyDer, keyDerLen);
    }

    if (OK == status)
    {
      /* recursive call to this method for the inner key */
      status = CRYPTO_deserializeAsymKey (MOC_ASYM(hwAccelCtx) pInnerKey, innerKeyLen, pMocCtx, pDeserializedKey);
      (void) DIGI_MEMSET_FREE(&pInnerKey, innerKeyLen);
    }
    else
    {
      /* Try for a software only deserialization */
      status = CRYPTO_deserializeKey ( MOC_ASYM(hwAccelCtx)
        pSerializedKey, serializedKeyLen, pSupportedAlgorithms,
        supportedAlgorithmCount, pDeserializedKey);      
    }
  }
#else
  else
#endif /* __ENABLE_DIGICERT_TAP__ */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#ifndef __ENABLE_DIGICERT_TAP__
  {
    /* Try for a software only deserialization */
    status = CRYPTO_deserializeKey ( MOC_ASYM(hwAccelCtx)
      pSerializedKey, serializedKeyLen, pSupportedAlgorithms,
      supportedAlgorithmCount, pDeserializedKey);
  }
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
exit:

  if (NULL != pNewKey)
  {
    CRYPTO_freeMocAsymKey(&pNewKey, NULL);
  }
#endif

  return status;
}

extern MSTATUS CRYPTO_deserializeAsymKeyWithCreds (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  MocCtx pMocCtx,
  ubyte *pPassword,
  ubyte4 passwordLen,
  void *pLoadCtx,
  AsymmetricKey *pDeserializedKey
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte *pTemp = NULL;
  ubyte4 tempLen = 0;
  byteBoolean freeTemp = TRUE;
  
#ifndef __ENABLE_DIGICERT_TAP__
  MOC_UNUSED(pLoadCtx);
#endif

  if (NULL == pSerializedKey || NULL == pDeserializedKey || (passwordLen && NULL == pPassword))
  {
    goto exit;
  }

  status = CRYPTO_deserializeAsymKey( MOC_ASYM(hwAccelCtx) pSerializedKey, serializedKeyLen, pMocCtx, pDeserializedKey);
  if (OK != status) /* not a tap key so try to get as a pkcs8 key */
  {
    /* PEM key should start with leading '-' char. Convert to DER */
    if ('-' == (char) pSerializedKey[0])
    {
      status = CA_MGMT_decodeCertificate(pSerializedKey, serializedKeyLen, &pTemp, &tempLen);
      if (OK != status)
        goto exit;
    } 
    else if (0x30 == pSerializedKey[0])  /* der key should start with 0x30 */
    {
      pTemp = pSerializedKey;
      tempLen = serializedKeyLen;
      freeTemp = FALSE;
    }
    else
    {
      goto exit; /* leave the error status from above */
    }

    status = PKCS_getPKCS8KeyEx( MOC_HW(hwAccelCtx) pTemp, tempLen, pPassword, passwordLen, pDeserializedKey);
    if (OK != status)
      goto exit;
  }
#ifdef __ENABLE_DIGICERT_TAP__
  else
  {
    switch(pDeserializedKey->type)
    {
      case akt_tap_rsa:

        if (NULL == pDeserializedKey->key.pRSA)
        {
          status = ERR_NULL_POINTER;
          goto exit;
        }

        status = CRYPTO_INTERFACE_TAP_loadWithCreds(pDeserializedKey->key.pRSA->pPrivateKey, pPassword, passwordLen, pLoadCtx);
        break;

#ifdef __ENABLE_DIGICERT_ECC__
      case akt_tap_ecc:

        if (NULL == pDeserializedKey->key.pECC)
        {
          status = ERR_NULL_POINTER;
          goto exit;
        }

        status = CRYPTO_INTERFACE_TAP_loadWithCreds(pDeserializedKey->key.pECC->pPrivateKey, pPassword, passwordLen, pLoadCtx);
        break;

      case akt_ecc:
      case akt_ecc_ed:
#endif
#ifdef __ENABLE_DIGICERT_DSA__
      case akt_dsa:
#endif
#ifdef __ENABLE_DIGICERT_PQC__
      case akt_qs:
      case akt_hybrid:
#endif
      case akt_rsa:
      case akt_rsa_pss:
         break; /* status still ok */

      default:
        status = ERR_BAD_KEY_TYPE;
    }
  }
#endif /* __ENABLE_DIGICERT_TAP__ */

exit:

  if (freeTemp && NULL != pTemp)
  {
    (void) DIGI_MEMSET_FREE(&pTemp, tempLen);
  }

  return status;
}

#if (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__))
#if (defined(__ENABLE_DIGICERT_TPM__))

extern MSTATUS KeySerializeTpmRsa (
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status;
  intBoolean isPrivate;
  sbyte4 cmpResult, theLen;
  ubyte4 keyBlobLen, keyDerLen, getAlgIdLen, getKeyDataLen;
  ubyte4 theTag, tLenLen, readBlobLen;
  ubyte *pKeyBlob = NULL;
  ubyte *pKeyDer = NULL;
  ubyte *pGetAlgId = NULL;
  ubyte *pGetKeyData = NULL;
  ubyte *pReadBlob = NULL;
#define MOC_TPM_RSA_BLOB_START_LEN 12
  ubyte pBlobStart[MOC_TPM_RSA_BLOB_START_LEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x01
  };
  ubyte pAlgId[MOP_TPM_12_RSA_KEY_ALG_ID_LEN] = {
    MOP_TPM_12_RSA_KEY_ALG_ID
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pAsymKey) || (NULL == ppSerializedKey) ||
       (NULL == pSerializedKeyLen) )
    goto exit;

  /* If the format is deserialize, call the appropriate routine.
   */
  if (deserialize == keyFormat)
  {
    status = ERR_NULL_POINTER;
    if ( (NULL == *ppSerializedKey) || (0 == *pSerializedKeyLen) )
      goto exit;

    /* Init this to the input. If it is a key blob, then this is correct. If it
     * ends up being DER, we'll change these variables.
     */
    pReadBlob = (*ppSerializedKey) + MOC_TPM_RSA_BLOB_START_LEN;
    readBlobLen = (*pSerializedKeyLen) - MOC_TPM_RSA_BLOB_START_LEN;

    /* Is the first byte 00 or 30?
     * If 30, it is DER.
     */
    if (0x30 == (*ppSerializedKey)[0])
    {
      /* Decode, then isolate the Blob
       */
      status = CRYPTO_findKeyInfoComponents (
        *ppSerializedKey, *pSerializedKeyLen, &pGetAlgId, &getAlgIdLen,
        &pGetKeyData, &getKeyDataLen, &isPrivate);
      if (OK != status)
        goto exit;

      /* Is the algId for TPM?
       */
      status = ASN1_compareOID (
        pAlgId, MOP_TPM_12_RSA_KEY_ALG_ID_LEN, pGetAlgId, getAlgIdLen,
        NULL, &cmpResult);
      if (OK != status)
        goto exit;

      status = ERR_INVALID_INPUT;
      if (0 != cmpResult)
        goto exit;

      /* This is TPM key data.
       * Get to the key blob, it is the OCTET string after the SEQUENCE.
       */
      status = ASN1_readTagAndLen (
        pGetKeyData, getKeyDataLen, &theTag, &theLen, &tLenLen);
      if (OK != status)
        goto exit;

      pReadBlob = pGetKeyData + tLenLen;
      readBlobLen = getKeyDataLen - tLenLen;

      /* This should be the OCTET STRING, get the actual value, that is the key
       * blob.
       */
      status = ASN1_readTagAndLen (
        pReadBlob, readBlobLen, &theTag, &theLen, &tLenLen);
      if (OK != status)
        goto exit;

      pReadBlob += tLenLen;
      readBlobLen -= tLenLen;
    }
    else
    {
      /* Make sure this is TPM RSA.
       */
      status = ERR_INVALID_INPUT;
      if (MOC_TPM_RSA_BLOB_START_LEN > *pSerializedKeyLen)
        goto exit;

      status = DIGI_MEMCMP (
        (void *)(*ppSerializedKey), pBlobStart, MOC_TPM_RSA_BLOB_START_LEN,
        &cmpResult);
      if (OK != status)
        goto exit;

      status = ERR_INVALID_INPUT;
      if (0 != cmpResult)
        goto exit;
    }

    /* Build the RSAKey from the data.
     */
    status = HSMRSAINFO_keyFromByteString (
      &(pAsymKey->key.pRSA), pReadBlob, readBlobLen);
    if (OK != status)
      goto exit;

    pAsymKey->type = keyblob_type_hsm_rsa;
    pAsymKey->key.pRSA->privateKey = TRUE;
    goto exit;
  }

  /* We're serializing.
   * If this is not a TPM RSA key return an error.
   */
  status = ERR_BAD_KEY;
  if (keyblob_type_hsm_rsa != pAsymKey->type)
    goto exit;

  /* If the caller is asking for the private key DER and this is not a private
   * key, error.
   */
  if ( (privateKeyInfoDer == keyFormat) &&
       (FALSE == pAsymKey->key.pRSA->privateKey) )
    goto exit;

  /* If requesting a blob, get a blob. If requesting DER, we're going to want a
   * blob anyway because the function that makes DER starts with the blob.
   */
  status = KEYBLOB_makeHSMRSAKeyBlob (
    pAsymKey->key.pRSA, &pKeyBlob, &keyBlobLen);
  if (OK != status)
    goto exit;

  /* If they requested the blob, set the return and we're done.
   */
  if (mocanaBlobVersion2 == keyFormat)
  {
    *ppSerializedKey = pKeyBlob;
    *pSerializedKeyLen = keyBlobLen;
    pKeyBlob = NULL;
    goto exit;
  }

  /* At this point, the format should be either pri key DER. We don't build PEM
   * directly, the contents of PEM is the DER and the caller should take care of
   * the PEM with any DER.
   * First, build the DER of the key data. This will be wrapped in PrivateKeyInfo.
   * This is
   *   SEQUENCE {
   *     OCTET STRING
   *     INTEGER
   *     INTEGER }
   */
  status = CA_MGMT_tpm12RsaKeyBlobToDer (
    pKeyBlob, keyBlobLen, RSA_N (pAsymKey->key.pRSA),
    RSA_E (pAsymKey->key.pRSA), &pKeyDer, &keyDerLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_makeKeyInfo (
    TRUE, (ubyte *)pAlgId, MOP_TPM_12_RSA_KEY_ALG_ID_LEN,
    pKeyDer, keyDerLen, ppSerializedKey, pSerializedKeyLen);

exit:

  if (NULL != pKeyBlob)
  {
    DIGI_FREE ((void **)&pKeyBlob);
  }
  if (NULL != pKeyDer)
  {
    DIGI_FREE ((void **)&pKeyDer);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_TPM__)) */
#endif /* (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__)) */

MOC_EXTERN MSTATUS CRYPTO_makeKeyInfo (
  intBoolean isPrivateKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte **ppKeyInfo,
  ubyte4 *pKeyInfoLen
  )
{
  MSTATUS status;
  ubyte4 lenToUse;
  ubyte derType;
  ubyte *pNewBuf = NULL;
  ubyte *pBufToUse;
  DER_ITEMPTR pSequence = NULL;

  status = DER_AddSequence (NULL, &pSequence);
  if (OK != status)
    goto exit;

  /* If this is private key, add the version.
   */
  derType = BITSTRING;
  if (TRUE == isPrivateKey)
  {
    status = DER_AddIntegerEx (pSequence, 0, NULL);
    if (OK != status)
      goto exit;

    derType = OCTETSTRING;
    pBufToUse = pKeyData;
    lenToUse = keyDataLen;
  }
  else
  {
    /* If public, we need to wrap the key in a BIT STRING, which will require an
     * unused bits octet at the beginning. We're going to call AddItem, which
     * just adds the data, so we need to add the 00 byte ourselves.
     * Incidentally, we don't call addBitString, because that will compute unused
     * bits based on trailing 0 bits, which is not what we want with
     * PublicKeyInfo.
     */
    status = DIGI_MALLOC ((void **)&pNewBuf, keyDataLen + 1);
    if (OK != status)
      goto exit;

    pNewBuf[0] = 0;
    status = DIGI_MEMCPY (
      (void *)(pNewBuf + 1), (void *)pKeyData, keyDataLen);
    if (OK != status)
      goto exit;

    pBufToUse = pNewBuf;
    lenToUse = keyDataLen + 1;
  }

  /* Add the algId.
   */
  status = DER_AddDERBuffer (pSequence, algIdLen, pAlgId, NULL);
  if (OK != status)
    goto exit;

  /* Add the key data. If public, it's wrapped in a BIT STRING.
   * If it's private, wrap it in an OCTET STRING.
   */
  status = DER_AddItem (
    pSequence, derType, lenToUse, pBufToUse, NULL);
  if (OK != status)
    goto exit;

  status = DER_Serialize (pSequence, ppKeyInfo, pKeyInfoLen);

exit:

  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }
  if (NULL != pSequence)
  {
    TREE_DeleteTreeItem ((TreeItem *)pSequence);
  }

  return (status);
}

MOC_EXTERN MSTATUS CRYPTO_findKeyInfoComponents (
  ubyte *pKeyInfo,
  ubyte4 keyInfoLen,
  ubyte **ppAlgId,
  ubyte4 *pAlgIdLen,
  ubyte **ppKeyData,
  ubyte4 *pKeyDataLen,
  intBoolean *isPrivate
  )
{
  MSTATUS status;
  ubyte4 bytesRead;
  MAsn1Element *pArray = NULL;

  /* If this is P8, we want
   *   SEQ {
   *     INT,
   *     AlgId,
   *     OCTET STRING,
   *     -ignore- }
   *
   * If this is X.509, we want
   *   SEQ {
   *     AlgId,
   *     BIT STRING }
   *
   * We'll cheat and create an array using OPTIONAL that works for both. Then we
   * look at what came out.
   */
  MAsn1TypeAndCount pTemplate[6] = {
    { MASN1_TYPE_SEQUENCE, 5 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_OCTET_STRING | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_BIT_STRING | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_ENCODED | MASN1_EXPLICIT | MASN1_OPTIONAL, 0 }
  };

  *isPrivate = FALSE;

  status = MAsn1CreateElementArray (
    pTemplate, 6, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pKeyInfo, keyInfoLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  *ppAlgId = pArray[2].encoding.pEncoding;
  *pAlgIdLen = pArray[2].encodingLen;

  /* If there is an integer (version) and OCTET STRING, this is a private key.
   */
  if ( (NULL != pArray[1].value.pValue) && (NULL != pArray[3].value.pValue) )
  {
    *isPrivate = TRUE;
    *ppKeyData = pArray[3].value.pValue;
    *pKeyDataLen = pArray[3].valueLen;
    goto exit;
  }

  /* It should be a public key. Make sure there is a BIT STRING.
   */
  status = ERR_INVALID_INPUT;
  if (NULL == pArray[4].value.pValue)
    goto exit;

  /* Skip the leading octet in the BIT STRING (unused bits).
   */
  *ppKeyData = pArray[4].value.pValue + 1;
  *pKeyDataLen = pArray[4].valueLen - 1;

  status = OK;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SERIALIZE__)) */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
extern MSTATUS
CRYPTO_setRSAParameters(MOC_RSA(hwAccelDescr hwAccelCtx)
                        AsymmetricKey* pKey, ubyte4 exponent,
                        const ubyte* modulus, ubyte4 modulusLen,
                        const ubyte* p, ubyte4 pLen,
                        const ubyte* q, ubyte4 qLen,
                        vlong **ppVlongQueue)
{
    MSTATUS status;

    if ( !pKey || !modulus)
        return ERR_NULL_POINTER;

    if (akt_rsa != pKey->type)
    {
        /* reset everything */
        if ( OK > (status = CRYPTO_createRSAKey( pKey, ppVlongQueue)))
             return status;
    }

    if ( p && pLen && q && qLen)
    {
        return RSA_setAllKeyParameters(MOC_RSA(hwAccelCtx)
                                       pKey->key.pRSA,
                                       exponent, modulus, modulusLen,
                                       p, pLen, q, qLen, ppVlongQueue);

    }

    return RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) pKey->key.pRSA,
                                        exponent, modulus, modulusLen, ppVlongQueue);
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*----------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_DSA__))
extern MSTATUS
CRYPTO_setDSAParameters( MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey,
                        const ubyte* p, ubyte4 pLen,
                        const ubyte* q, ubyte4 qLen,
                        const ubyte* g, ubyte4 gLen,
                        const ubyte* y, ubyte4 yLen,
                        const ubyte* x, ubyte4 xLen,
                        vlong **ppVlongQueue)
{
    MSTATUS status;

    if ( !pKey || !q || !q || !g )
        return ERR_NULL_POINTER;

    if (!pLen || !qLen || !gLen )
        return ERR_INVALID_ARG;

    if (akt_dsa != pKey->type)
    {
        /* reset everything */
        if ( OK > (status = CRYPTO_createDSAKey( pKey, ppVlongQueue)))
             return status;
    }

    if ( x && xLen)
    {
        return DSA_setAllKeyParameters(MOC_DSA(hwAccelCtx)
                                       pKey->key.pDSA,
                                       p, pLen, q, qLen,
                                       g, gLen, x, xLen, ppVlongQueue);

    }
    else if ( y && yLen)
    {
        return DSA_setPublicKeyParameters(MOC_DSA(hwAccelCtx) pKey->key.pDSA,
                                       p, pLen, q, qLen,
                                       g, gLen, y, yLen,
                                       ppVlongQueue);
    }
    return ERR_INVALID_ARG;
}

#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
extern ubyte4 CRYPTO_getECCurveId (
    const AsymmetricKey *pKey
    )
{
    MSTATUS status;
    ubyte4 curveId = 0;

    if (NULL != pKey)
        if (OK > (status = EC_getCurveIdFromKey(pKey->key.pECC, &curveId)))
            curveId = 0;

    return curveId;
}
#endif

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
extern MSTATUS CRYPTO_setECCParameters(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    AsymmetricKey* pKey,
    ubyte4 curveId,
    const ubyte* pPoint,
    ubyte4 pointLen,
    const ubyte* pScalar,
    ubyte4 scalarLen
    )
{
    MSTATUS status;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    PEllipticCurvePtr pCurve;
#endif

    if ( (NULL == pKey) || (NULL == pPoint && NULL == pScalar) )
        return ERR_NULL_POINTER;

    /* CRYPTO_createECCKey(Ex) will destroy any previously existing key for us */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__

    if (OK > (status = CRYPTO_createECCKeyEx(pKey, curveId)))
        return status;

    return CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) pKey->key.pECC, (ubyte *) pPoint, pointLen, (ubyte *) pScalar, scalarLen);

#else
    switch (curveId)
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case cid_EC_P192:
            pCurve = EC_P192;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case cid_EC_P224:
            pCurve = EC_P224;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case cid_EC_P256:
            pCurve = EC_P256;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case cid_EC_P384:
            pCurve = EC_P384;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case cid_EC_P521:
            pCurve = EC_P521;
            break;
#endif

        default:
            return ERR_EC_UNSUPPORTED_CURVE;
    }

    if (OK > (status = CRYPTO_createECCKey(pKey, pCurve)))
        return status;

    /* Set the point and scalar within the ECC key */
    return EC_setKeyParametersEx(pKey->key.pECC, (ubyte *) pPoint, pointLen, (ubyte *) pScalar, scalarLen);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
}

#ifdef __ENABLE_DIGICERT_PQC__
extern MSTATUS CRYPTO_setHybridParameters(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    ubyte4 clAlgId,
    ubyte4 qsAlgId,
    ubyte *pPubKey,
    ubyte4 pubKeyLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 qsPubLen = 0;
    ECCKey *pEccKey = NULL;
    QS_CTX *pQsCtx = NULL;

    if (NULL == pKey || NULL == pPubKey)
        goto exit;
        
    /* qsPubLen is first 4 bytes */
    qsPubLen = ((ubyte4) pPubKey[0]) | (((ubyte4)pPubKey[1]) << 8) | 
               (((ubyte4)pPubKey[2]) << 16) | (((ubyte4)pPubKey[3]) << 24);

    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, qsAlgId);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_setPublicKey(pQsCtx, pPubKey + 4, qsPubLen);
    if (OK != status)
        goto exit;

    /* uninit any existing key, need to now so RSA key can be deserialized if needbe */
    status = CRYPTO_uninitAsymmetricKey(pKey, NULL);
    if (OK != status)
        goto exit;

    if (clAlgId < cid_RSA_2048_PKCS15) /* ECC */
    {
        status = CRYPTO_INTERFACE_EC_newKeyAux(clAlgId, &pEccKey);
        if (OK != status)
          goto exit;

        status = CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) pEccKey, pPubKey + 4 + qsPubLen, pubKeyLen - 4 - qsPubLen, 
                                                         NULL, 0);
        if (OK != status)
            goto exit;

        pKey->key.pECC = pEccKey; pEccKey = NULL;
    }
    else /* RSA */
    {
        status = DeserializeRsaKey(MOC_ASYM(hwAccelCtx) pPubKey + 4 + qsPubLen, pubKeyLen - 4 - qsPubLen, pKey, NULL);
        if (OK != status)
            goto exit;
    }

    pKey->type = akt_hybrid;
    pKey->clAlg = clAlgId;
    pKey->pQsCtx = pQsCtx; pQsCtx = NULL;
        
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
    
    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */
#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_loadAsymmetricKey (
  AsymmetricKey *pAsymKey,
  ubyte4 keyType,
  void **ppAlgKey
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pAsymKey) || (NULL == ppAlgKey) )
    goto exit;

  if (NULL == *ppAlgKey)
    goto exit;

  /* Make sure the key object is clear.
   */
  status = CRYPTO_initAsymmetricKey (pAsymKey);
  if (OK != status)
    goto exit;

  switch (keyType)
  {
    default:
      status = ERR_BAD_KEY_TYPE;
      goto exit;

    case akt_rsa:
    case akt_tap_rsa:
      pAsymKey->key.pRSA = (RSAKey *)(*ppAlgKey);
      pAsymKey->type = keyType;
      break;

#if (defined(__ENABLE_DIGICERT_DSA__))
    case akt_dsa:
      pAsymKey->key.pDSA = (DSAKey *)(*ppAlgKey);
      pAsymKey->type = akt_dsa;
      break;
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
    case akt_ecc:
    case akt_ecc_ed:
    case akt_tap_ecc:
      pAsymKey->key.pECC = (ECCKey *)(*ppAlgKey);
      pAsymKey->type = keyType;
      break;
#endif

#if (defined(__ENABLE_DIGICERT_PQC__))
    case akt_hybrid:

      pAsymKey->pQsCtx = (QS_CTX *) (((HybridKey *)(*ppAlgKey))->pKey2);
      pAsymKey->type = akt_hybrid;
      pAsymKey->clAlg = ((HybridKey *)(*ppAlgKey))->clAlg;

      if (pAsymKey->clAlg < cid_RSA_2048_PKCS15) /* ECC */
      {
          pAsymKey->key.pECC = (ECCKey *) (((HybridKey *)(*ppAlgKey))->pKey1);
      }
      else /* RSA */
      {
          pAsymKey->key.pRSA = (RSAKey *) (((HybridKey *)(*ppAlgKey))->pKey1);
      }

      ((HybridKey *)(*ppAlgKey))->pKey1 = NULL;
      ((HybridKey *)(*ppAlgKey))->pKey2 = NULL;
      ((HybridKey *)(*ppAlgKey))->clAlg = 0;
      break;
      
    case akt_qs:
      pAsymKey->pQsCtx = (QS_CTX *)(*ppAlgKey);
      pAsymKey->type = akt_qs;
      break;
#endif

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
    case akt_moc:
    case akt_custom:
      pAsymKey->key.pMocAsymKey = (MocAsymKey )(*ppAlgKey);
      pAsymKey->type = keyType;
      break;
#endif
  }

  /* If we reach this point, everything worked, so NULL out the AlgKey.
   */
  if (akt_hybrid != keyType)
    *ppAlgKey = NULL;

exit:

  return (status);
}
