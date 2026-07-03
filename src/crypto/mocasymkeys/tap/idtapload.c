/*
 * idtapload.c
 *
 * load keys by TAP ID.
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
 *
 */

#include "../../../crypto/mocasymkeys/tap/idtap.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__)

#include "../../../crypto_interface/cryptointerface.h"

MSTATUS IdTapLoadKeyData (
  TAP_Buffer *pKeyId,
  TAP_KEY_ALGORITHM expectedKeyAlgo,
  MocAsymKey pMocAsymKey,
  TAP_Key **ppOutKey
  )
{
  MSTATUS status = ERR_NULL_POINTER, status2 = OK;
  TAP_CredentialList *pKeyCredentials = NULL;
  TAP_EntityCredentialList *pEntityCredentials = NULL;
  TAP_Context *pTapContext = NULL;
  TAP_ErrorContext errContext = {0};
  TAP_ErrorContext *pErrContext = &errContext;
  ubyte4 idInt = 0;
  TAP_KeyInfo keyInfo = {0};
  TAP_KEY_SIZE keySize = 0;
  ubyte subType = 0;
  TapOperation op;
  byteBoolean tapOpSet = FALSE;
  
  if (NULL == pKeyId || NULL == ppOutKey)
      goto exit;

  /* Ids for at least NanoRoot must be 4 bytes, this check and the parse below can be moved out if more SMPs use this method */
  status = ERR_INVALID_INPUT;
  if (pKeyId->bufferLen != 4)
      goto exit;

  idInt = (((ubyte4) pKeyId->pBuffer[3]) << 24) | (((ubyte4) pKeyId->pBuffer[2]) << 16) | (((ubyte4) pKeyId->pBuffer[1]) << 8) | ((ubyte4) pKeyId->pBuffer[0]);

  status = TAP_parse_algorithm_info(idInt, &keyInfo.keyAlgorithm, &keySize, &subType);
  if (OK != status)
      goto exit;

  /* IMPORTANT! key algorithm must match! */
  if (expectedKeyAlgo != keyInfo.keyAlgorithm)
  {
    status = ERR_BAD_KEY_TYPE;
    goto exit;
  }

  /* set rest of keyInfo */
  switch (keyInfo.keyAlgorithm)
  {
#ifndef __DISABLE_DIGICERT_RSA__
    case TAP_KEY_ALGORITHM_RSA:
      op = tap_rsa_sign;
      keyInfo.algKeyInfo.rsaInfo.keySize = keySize;
      if (TAP_KEY_SIZE_4096 == keySize || TAP_KEY_SIZE_8192 == keySize)
        keyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
      else
        keyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;

      break;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    case TAP_KEY_ALGORITHM_ECC:
      op = tap_ecc_sign;
      keyInfo.algKeyInfo.eccInfo.curveId = subType;
      if (TAP_ECC_CURVE_NIST_P521 == subType)
        keyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
      else
        keyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;

      break;
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    case TAP_KEY_ALGORITHM_MLDSA:
      op = tap_qs_sign;
      keyInfo.algKeyInfo.pqcInfo.qsAlg = subType;
      break;
#endif

    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;
  }
  tapOpSet = TRUE;

  if (g_pFuncPtrGetTapContext != NULL)
  {
    if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                    &pEntityCredentials,
                    &pKeyCredentials,
                    (void *)pMocAsymKey, op, 1/*get context*/)))
    {
      goto exit;
    }
  }
  else
  {
    status = ERR_NOT_IMPLEMENTED;
    goto exit;
  }

  status = TAP_importKeyFromID(pTapContext, pEntityCredentials, &keyInfo, pKeyId, NULL, pKeyCredentials, ppOutKey, pErrContext);

exit:

  if (g_pFuncPtrGetTapContext != NULL && TRUE == tapOpSet)
  {
    status2 = g_pFuncPtrGetTapContext(
      &pTapContext, &pEntityCredentials, &pKeyCredentials, (void *) pMocAsymKey,
      op, 0 /*release context*/);
  }

  /* if we failed in the cleanup, record the failure */
  if ((OK == status) && (OK > status2))
    status = status2;

  return status;
}
#endif
