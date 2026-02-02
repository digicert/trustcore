/*
 * crypto_interface_ecc.c
 *
 * Cryptographic Interface specification for ECC.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_EDDSA_INTERNAL__

#include "../crypto/mocasym.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec_priv.h"
#include "../crypto/primeec.h"
#include "../crypto/ecc_edwards_dsa.h"
#include "../crypto/crypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_eddsa.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EDDSA__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#define MOC_EDDSA_SIGN(_status, _pKey, _pMessage, _messageLen, _pSignature, _bufferSize, _pSignatureLen, _preHash, _pCtx, _ctxLen, _pExtCtx) \
{ \
  BulkHashAlgo *_pShaSuite = NULL;                             \
  if (cid_EC_Ed25519 == _pKey->curveId)                        \
    _status = CRYPTO_getECCHashAlgo(ht_sha512, &_pShaSuite);   \
  else if (cid_EC_Ed448 == _pKey->curveId)                     \
    _status = CRYPTO_getECCHashAlgo(ht_shake256, &_pShaSuite); \
  else                                                         \
    _status = ERR_EC_UNSUPPORTED_CURVE;                        \
  if (OK != _status)                                           \
    goto exit;                                                 \
  _status = edDSA_Sign(MOC_ECC(hwAccelCtx) (edECCKey *) _pKey->pEdECCKey, _pMessage, _messageLen, _pSignature, _bufferSize, _pSignatureLen, _pShaSuite, _preHash, _pCtx, _ctxLen, _pExtCtx); \
}
#else
#define MOC_EDDSA_SIGN(_status, _pKey, _pMessage, _messageLen, _pSignature, _bufferSize, _pSignatureLen, _preHash, _pCtx, _ctxLen, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#define MOC_EDDSA_VERIFY(_status, _pKey, _pMessage, _messageLen, _pSignature, _signatureLen, _pVerifyStatus, _preHash, _pCtx, _ctxLen, _pExtCtx) \
{ \
  BulkHashAlgo *_pShaSuite = NULL;                             \
  if (cid_EC_Ed25519 == _pKey->curveId)                        \
    _status = CRYPTO_getECCHashAlgo(ht_sha512, &_pShaSuite);   \
  else if (cid_EC_Ed448 == _pKey->curveId)                     \
    _status = CRYPTO_getECCHashAlgo(ht_shake256, &_pShaSuite); \
  else                                                         \
    _status = ERR_EC_UNSUPPORTED_CURVE;                        \
  if (OK != _status)                                           \
    goto exit;                                                 \
  _status = edDSA_VerifySignature(MOC_ECC(hwAccelCtx) (edECCKey *) _pKey->pEdECCKey, _pMessage, _messageLen, _pSignature, _signatureLen, _pVerifyStatus, _pShaSuite, _preHash, _pCtx, _ctxLen, _pExtCtx); \
}
#else
#define MOC_EDDSA_VERIFY(_status, _pKey, _pMessage, _messageLen, _pSignature, _signatureLen, _pVerifyStatus, _preHash, _pCtx, _ctxLen, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#define MOC_EDDSA_INIT_SIGN_PREHASH(_status, _pEdDSA_ctx, _pKey, _pCtx, _ctxLen, _pExtCtx) \
{ \
  BulkHashAlgo *_pShaSuite = NULL;                             \
  if (cid_EC_Ed25519 == _pKey->curveId)                        \
    _status = CRYPTO_getECCHashAlgo(ht_sha512, &_pShaSuite);   \
  else if (cid_EC_Ed448 == _pKey->curveId)                     \
    _status = CRYPTO_getECCHashAlgo(ht_shake256, &_pShaSuite); \
  else                                                         \
    _status = ERR_EC_UNSUPPORTED_CURVE;                        \
  if (OK != _status)                                           \
    goto exit;                                                 \
  _status = edDSA_initSignPreHash(MOC_ECC(hwAccelCtx) _pEdDSA_ctx, (edECCKey *) _pKey->pEdECCKey, _pShaSuite, _pCtx, _ctxLen, _pExtCtx); \
  if (OK != _status)                                           \
    goto exit;                                                 \
  _pEdDSA_ctx->enabled = 0;                                    \
}
#else
#define MOC_EDDSA_INIT_SIGN_PREHASH(_status, _pEdDSA_ctx, _pKey, _pCtx, _ctxLen, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#define MOC_EDDSA_INIT_VERIFY(_status, _pEdDSA_ctx, _pKey, _pSignature, _signatureLen, _preHash, _pCtx, _ctxLen, _pExtCtx) \
{ \
  BulkHashAlgo *_pShaSuite = NULL;                             \
  if (cid_EC_Ed25519 == _pKey->curveId)                        \
    _status = CRYPTO_getECCHashAlgo(ht_sha512, &_pShaSuite);   \
  else if (cid_EC_Ed448 == _pKey->curveId)                     \
    _status = CRYPTO_getECCHashAlgo(ht_shake256, &_pShaSuite); \
  else                                                         \
    _status = ERR_EC_UNSUPPORTED_CURVE;                        \
  if (OK != _status)                                           \
    goto exit;                                                 \
  _status = edDSA_initVerify(MOC_ECC(hwAccelCtx) _pEdDSA_ctx, (edECCKey *) _pKey->pEdECCKey, _pSignature, _signatureLen, _pShaSuite, _preHash, _pCtx, _ctxLen, _pExtCtx); \
  if (OK != _status)                                           \
    goto exit;                                                 \
  _pEdDSA_ctx->enabled = 0;                                    \
}
#else
#define MOC_EDDSA_INIT_VERIFY(_status, _pEdDSA_ctx, _pKey, _pSignature, _signatureLen, _preHash, _pCtx, _ctxLen, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#define MOC_EDDSA_UPDATE(_status, _pEdDSA_ctx, _pMessage, _messageLen, _pExtCtx) \
  _status = edDSA_update(MOC_ECC(hwAccelCtx) _pEdDSA_ctx, _pMessage, _messageLen, _pExtCtx);
#else
#define MOC_EDDSA_UPDATE(_status, _pEdDSA_ctx, _pMessage, _messageLen, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#define MOC_EDDSA_FINAL_SIGN(_status, _pEdDSA_ctx, _pSignature, _bufferSize, _pSignatureLen, _pExtCtx) \
  _status = edDSA_finalSign(MOC_ECC(hwAccelCtx) _pEdDSA_ctx, _pSignature, _bufferSize, _pSignatureLen, _pExtCtx);
#else
#define MOC_EDDSA_FINAL_SIGN(_status, _pEdDSA_ctx, _pSignature, _bufferSize, _pSignatureLen, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_ECC__)) && \
    (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
#define MOC_EDDSA_FINAL_VERIFY(_status, _pEdDSA_ctx, _pVerifyStatus, _pExtCtx) \
  _status = edDSA_finalVerify(MOC_ECC(hwAccelCtx) _pEdDSA_ctx, _pVerifyStatus, _pExtCtx);
#else
#define MOC_EDDSA_FINAL_VERIFY(_status, _pEdDSA_ctx, _pVerifyStatus, _pExtCtx) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_Sign(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                                               ubyte4 bufferSize, ubyte4 *pSignatureLen, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EDDSA_SIGN(status, pKey, pMessage, messageLen, pSignature, bufferSize, pSignatureLen, preHash, pCtx, ctxLen, pExtCtx)
  }

exit:

  return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_VerifySignature(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature,
                                                          ubyte4 signatureLen, ubyte4 *pVerifyStatus, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EDDSA_VERIFY(status, pKey, pMessage, messageLen, pSignature, signatureLen, pVerifyStatus, preHash, pCtx, ctxLen, pExtCtx)
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_initSignPreHash(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ECCKey *pKey, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pEdDSA_ctx)
      goto exit;

    /* even though there's no implementation, copy the enabled flag and key pointer so an update or final call can error correctly */
    pEdDSA_ctx->enabled = pKey->enabled;
    pEdDSA_ctx->pECCKey = (void *) pKey;

    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EDDSA_INIT_SIGN_PREHASH(status, pEdDSA_ctx, pKey, pCtx, ctxLen, pExtCtx)
  }

exit:

  return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_initVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ECCKey *pKey, ubyte *pSignature,
                                                     ubyte4 signatureLen, byteBoolean preHash, ubyte *pCtx, ubyte4 ctxLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    if (NULL == pEdDSA_ctx)
      goto exit;

    /* even though there's no implementation, copy the enabled flag and key pointer so an update or final call can error correctly */
    pEdDSA_ctx->enabled = pKey->enabled;
    pEdDSA_ctx->pECCKey = (void *) pKey;

    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EDDSA_INIT_VERIFY(status, pEdDSA_ctx, pKey, pSignature, signatureLen, preHash, pCtx, ctxLen, pExtCtx)
  }

exit:

  return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_update(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pMessage, ubyte4 messageLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pEdDSA_ctx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pEdDSA_ctx->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EDDSA_UPDATE(status, pEdDSA_ctx, pMessage, messageLen, pExtCtx)
  }

exit:

  return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_finalSign(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte *pSignature, ubyte4 bufferSize, ubyte4 *pSignatureLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pEdDSA_ctx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pEdDSA_ctx->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EDDSA_FINAL_SIGN(status, pEdDSA_ctx, pSignature, bufferSize, pSignatureLen, pExtCtx);
  }

exit:

  return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EdDSA_finalVerify(MOC_ECC(hwAccelDescr hwAccelCtx) edDSA_CTX *pEdDSA_ctx, ubyte4 *pVerifyStatus, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pEdDSA_ctx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pEdDSA_ctx->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_EDDSA_FINAL_VERIFY(status, pEdDSA_ctx, pVerifyStatus, pExtCtx)
  }

exit:

  return status;
}
#endif /* #ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EDDSA__ */
