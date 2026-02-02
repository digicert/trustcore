/*
 * rsakeytap.c
 *
 * Operator for TAP version of RSA MocAsym Key.
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

#include "../../../crypto/mocasymkeys/mocsw/commonrsa.h"
#include "../../../crypto/mocasymkeys/tap/rsatap.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_TAP__)

 MOC_EXTERN MSTATUS KeyOperatorRsaTap (
   MocAsymKey pMocAsymKey,
   MocCtx pMocCtx,
   keyOperation keyOp,
   void *pInputInfo,
   void *pOutputInfo,
   struct vlong **ppVlongQueue
   )
 {
   MSTATUS status;
   serializedKeyFormat keyFormat;

   switch (keyOp)
   {
     default:
       status = ERR_NOT_IMPLEMENTED;
       goto exit;

      case MOC_ASYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        status = OK;
        *((ubyte4 *)(pOutputInfo)) = MOC_LOCAL_TYPE_RSA;
      }
      break;

     case MOC_ASYM_OP_CREATE:
     case MOC_ASYM_OP_CREATE_PUB:
     case MOC_ASYM_OP_CREATE_PRI:
       status = RsaTapCreate (pMocAsymKey, pInputInfo, keyOp);
       break;

     case MOC_ASYM_OP_GENERATE:
       status = RsaTapGenerateKeyPair (
         pMocCtx, (MKeyPairGenInfo *)pInputInfo, (MKeyPairGenResult *)pOutputInfo,
         ppVlongQueue);
       break;

    case MOC_ASYM_OP_PUB_FROM_PRI:
      status = RsaTapGetPubFromPri (
        pMocAsymKey, (MocAsymKey *)pOutputInfo, ppVlongQueue);
      break;

     case MOC_ASYM_OP_GET_SECURITY_SIZE:
       status = RsaTapGetSecuritySize (pMocAsymKey, (ubyte4 *)pOutputInfo);
       break;

     case MOC_ASYM_OP_GET_LOCAL_KEY:
       status = ERR_NULL_POINTER;
       if (NULL != pOutputInfo)
       {
         status = OK;
         *((void **)pOutputInfo) = NULL;

         if (NULL != pMocAsymKey->pKeyData)
         {
           *((void **)pOutputInfo) =
             (void *)(((MRsaTapKeyData *)(pMocAsymKey->pKeyData))->pKey);
         }
       }

       break;

     case MOC_ASYM_OP_SERIALIZE:
       keyFormat = noFormat;
       if (NULL != pInputInfo)
         keyFormat = *((serializedKeyFormat *)pInputInfo);

       status = RsaTapSerializeKey (
         pMocAsymKey, keyFormat, (MKeyOperatorDataReturn *)pOutputInfo);
       break;

     case MOC_ASYM_OP_DESERIALIZE:
       status = RsaTapDeserializeKey (
         pMocAsymKey, (MKeyOperatorData *)pInputInfo);
       break;

     case MOC_ASYM_OP_FREE:
       status = RsaTapFreeKey (pMocAsymKey);
       break;
   }

 exit:

   return (status);
 }

 #endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

