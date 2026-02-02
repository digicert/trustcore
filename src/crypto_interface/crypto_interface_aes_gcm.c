/*
 * crypto_interface_aes_gcm.c
 *
 * Cryptographic Interface specification for AES-GCM.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/aes.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/gcm.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_aes_gcm.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../crypto_interface/crypto_interface_aes_gcm_tap.h"
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_CREATE_256B(_pGcmCtx, _pKeyData, _keyLen, _encrypt)       \
    _pGcmCtx = GCM_createCtx_256b(MOC_SYM(hwAccelCtx) _pKeyData, _keyLen, _encrypt);
#else
#define MOC_AES_GCM_CREATE_256B(_pGcmCtx, _pKeyData, _keyLen, _encrypt)
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_UPDATE_NONCE_256B(_status, _pCtx, _pNonce, _nonceLen)     \
    _status = GCM_update_nonce_256b(MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nonceLen);
#else
#define MOC_AES_GCM_UPDATE_NONCE_256B(_status, _pCtx, _pNonce, _nonceLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_UPDATE_AAD_256B(_status, _pCtx, _pAad, _aadLen)           \
    _status = GCM_update_aad_256b(MOC_SYM(hwAccelCtx) _pCtx, _pAad, _aadLen);
#else
#define MOC_AES_GCM_UPDATE_AAD_256B(_status, _pCtx, _pAad, _aadLen)           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_UPDATE_DATA_256B(_status, _pCtx, _pData, _dataLen)        \
    _status = GCM_update_data_256b(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_DATA_256B(_status, _pCtx, _pData, _dataLen)        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_FINAL_EX_256B(_status, _pCtx, _pTag, _tagLen)             \
    _status = GCM_final_ex_256b(MOC_SYM(hwAccelCtx) _pCtx, _pTag, _tagLen);
#else
#define MOC_AES_GCM_FINAL_EX_256B(_status, _pCtx, _pTag, _tagLen)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_DELETE_256B(_status, _pGcmCtx)                            \
    _status = GCM_deleteCtx_256b(MOC_SYM(hwAccelCtx) _pGcmCtx);
#else
#define MOC_AES_GCM_DELETE_256B(_status, _pGcmCtx)                            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_CLONE_256B(_status, _pCtx, _ppCtx)                        \
    _status = GCM_clone_256b(MOC_SYM(hwAccelCtx) _pCtx, _ppCtx);
#else
#define MOC_AES_GCM_CLONE_256B(_status, _pCtx, _ppCtx)                        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_INIT_256B(_status, _pCtx, _pNonce, _nLen, _pAad, _aadLen) \
    _status = GCM_init_256b(MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nLen, _pAad, _aadLen);
#else
#define MOC_AES_GCM_INIT_256B(_status, _pCtx, _pNonce, _nLen, _pAad, _aadLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_UPDATE_ENCRYPT_256B(_status, _pCtx, _pData, _dataLen)     \
    _status = GCM_update_encrypt_256b(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_ENCRYPT_256B(_status, _pCtx, _pData, _dataLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_UPDATE_DECRYPT_256B(_status, _pCtx, _pData, _dataLen)     \
    _status = GCM_update_decrypt_256b(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_DECRYPT_256B(_status, _pCtx, _pData, _dataLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_FINAL_256B(_status, _pCtx, _pTag)                         \
    _status = GCM_final_256b(MOC_SYM(hwAccelCtx) _pCtx, _pTag);
#else
#define MOC_AES_GCM_FINAL_256B(_status, _pCtx, _pTag)                         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_256B__))
#define MOC_AES_GCM_DO_CIPHER_256B(_s, _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc) \
    _s = GCM_cipher_256b(MOC_SYM(hwAccelCtx) _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc);
#else
#define MOC_AES_GCM_DO_CIPHER_256B(_s, _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc) \
    _s = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_CREATE_4K(_pGcmCtx, _pKeyData, _keyLen, _encrypt)       \
    _pGcmCtx = GCM_createCtx_4k(MOC_SYM(hwAccelCtx) _pKeyData, _keyLen, _encrypt);
#else
#define MOC_AES_GCM_CREATE_4K(_pGcmCtx, _pKeyData, _keyLen, _encrypt)
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_UPDATE_NONCE_4K(_status, _pCtx, _pNonce, _nonceLen)     \
    _status = GCM_update_nonce_4k(MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nonceLen);
#else
#define MOC_AES_GCM_UPDATE_NONCE_4K(_status, _pCtx, _pNonce, _nonceLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_UPDATE_AAD_4K(_status, _pCtx, _pAad, _aadLen)           \
    _status = GCM_update_aad_4k(MOC_SYM(hwAccelCtx) _pCtx, _pAad, _aadLen);
#else
#define MOC_AES_GCM_UPDATE_AAD_4K(_status, _pCtx, _pAad, _aadLen)           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_UPDATE_DATA_4K(_status, _pCtx, _pData, _dataLen)        \
    _status = GCM_update_data_4k(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_DATA_4K(_status, _pCtx, _pData, _dataLen)        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_FINAL_EX_4K(_status, _pCtx, _pTag, _tagLen)             \
    _status = GCM_final_ex_4k(MOC_SYM(hwAccelCtx) _pCtx, _pTag, _tagLen);
#else
#define MOC_AES_GCM_FINAL_EX_4K(_status, _pCtx, _pTag, _tagLen)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_DELETE_4K(_status, _pGcmCtx)                            \
    _status = GCM_deleteCtx_4k(MOC_SYM(hwAccelCtx) _pGcmCtx);
#else
#define MOC_AES_GCM_DELETE_4K(_status, _pGcmCtx)                            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_CLONE_4K(_status, _pCtx, _ppCtx)                        \
    _status = GCM_clone_4k(MOC_SYM(hwAccelCtx) _pCtx, _ppCtx);
#else
#define MOC_AES_GCM_CLONE_4K(_status, _pCtx, _ppCtx)                        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_INIT_4K(_status, _pCtx, _pNonce, _nLen, _pAad, _aadLen) \
    _status = GCM_init_4k(MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nLen, _pAad, _aadLen);
#else
#define MOC_AES_GCM_INIT_4K(_status, _pCtx, _pNonce, _nLen, _pAad, _aadLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_UPDATE_ENCRYPT_4K(_status, _pCtx, _pData, _dataLen)     \
    _status = GCM_update_encrypt_4k(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_ENCRYPT_4K(_status, _pCtx, _pData, _dataLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_UPDATE_DECRYPT_4K(_status, _pCtx, _pData, _dataLen)     \
    _status = GCM_update_decrypt_4k(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_DECRYPT_4K(_status, _pCtx, _pData, _dataLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_FINAL_4K(_status, _pCtx, _pTag)                         \
    _status = GCM_final_4k(MOC_SYM(hwAccelCtx) _pCtx, _pTag);
#else
#define MOC_AES_GCM_FINAL_4K(_status, _pCtx, _pTag)                         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_4K__))
#define MOC_AES_GCM_DO_CIPHER_4K(_s, _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc) \
    _s = GCM_cipher_4k(MOC_SYM(hwAccelCtx) _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc);
#else
#define MOC_AES_GCM_DO_CIPHER_4K(_s, _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc) \
    _s = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_CREATE_64K(_pGcmCtx, _pKeyData, _keyLen, _encrypt)       \
    _pGcmCtx = GCM_createCtx_64k(MOC_SYM(hwAccelCtx) _pKeyData, _keyLen, _encrypt);
#else
#define MOC_AES_GCM_CREATE_64K(_pGcmCtx, _pKeyData, _keyLen, _encrypt)
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_UPDATE_NONCE_64K(_status, _pCtx, _pNonce, _nonceLen)     \
    _status = GCM_update_nonce_64k(MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nonceLen);
#else
#define MOC_AES_GCM_UPDATE_NONCE_64K(_status, _pCtx, _pNonce, _nonceLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_UPDATE_AAD_64K(_status, _pCtx, _pAad, _aadLen)           \
    _status = GCM_update_aad_64k(MOC_SYM(hwAccelCtx) _pCtx, _pAad, _aadLen);
#else
#define MOC_AES_GCM_UPDATE_AAD_64K(_status, _pCtx, _pAad, _aadLen)           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_UPDATE_DATA_64K(_status, _pCtx, _pData, _dataLen)        \
    _status = GCM_update_data_64k(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_DATA_64K(_status, _pCtx, _pData, _dataLen)        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_FINAL_EX_64K(_status, _pCtx, _pTag, _tagLen)             \
    _status = GCM_final_ex_64k(MOC_SYM(hwAccelCtx) _pCtx, _pTag, _tagLen);
#else
#define MOC_AES_GCM_FINAL_EX_64K(_status, _pCtx, _pTag, _tagLen)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_DELETE_64K(_status, _pGcmCtx)                            \
    _status = GCM_deleteCtx_64k(MOC_SYM(hwAccelCtx) _pGcmCtx);
#else
#define MOC_AES_GCM_DELETE_64K(_status, _pGcmCtx)                            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_CLONE_64K(_status, _pCtx, _ppCtx)                        \
    _status = GCM_clone_64k(MOC_SYM(hwAccelCtx) _pCtx, _ppCtx);
#else
#define MOC_AES_GCM_CLONE_64K(_status, _pCtx, _ppCtx)                        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_INIT_64K(_status, _pCtx, _pNonce, _nLen, _pAad, _aadLen) \
    _status = GCM_init_64k(MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nLen, _pAad, _aadLen);
#else
#define MOC_AES_GCM_INIT_64K(_status, _pCtx, _pNonce, _nLen, _pAad, _aadLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_UPDATE_ENCRYPT_64K(_status, _pCtx, _pData, _dataLen)     \
    _status = GCM_update_encrypt_64k(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_ENCRYPT_64K(_status, _pCtx, _pData, _dataLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_UPDATE_DECRYPT_64K(_status, _pCtx, _pData, _dataLen)     \
    _status = GCM_update_decrypt_64k(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_AES_GCM_UPDATE_DECRYPT_64K(_status, _pCtx, _pData, _dataLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_FINAL_64K(_status, _pCtx, _pTag)                         \
    _status = GCM_final_64k(MOC_SYM(hwAccelCtx) _pCtx, _pTag);
#else
#define MOC_AES_GCM_FINAL_64K(_status, _pCtx, _pTag)                         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_GCM_64K__))
#define MOC_AES_GCM_DO_CIPHER_64K(_s, _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc) \
    _s = GCM_cipher_64k(MOC_SYM(hwAccelCtx) _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc);
#else
#define MOC_AES_GCM_DO_CIPHER_64K(_s, _pCtx, _pN, _nLen, _pA, _aLen, _pD, _dLen, _tLen, _enc) \
    _s = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_GCM_256B__

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_ex_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte4 tagLen
  );

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_GCM_createCtx_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyData,
  sbyte4 keyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  void *pPtr = NULL;
  MocSymCtx pNewSymCtx = NULL;
  gcm_ctx_256b *pGcmCtx = NULL;

  /* Determine if we have an AES-GCM implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_gcm, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    if ( (0 != keyLen) && (NULL == pKeyData) )
      goto exit;

    /* Create a new MocSymCtx and load the key data in */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, pKeyData, (ubyte4)keyLen, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* We do not want to call init here, we still need the IV and AAD from the
     * init call. Instead we will create an empty object and allocate the GCM
     * shell. When we recieve the IV and AAD in GCM_init_*, we will perform
     * the init. */
    status = DIGI_CALLOC(&pPtr, 1, sizeof(gcm_ctx_256b));
    if (OK != status)
      goto exit;

    pGcmCtx = (gcm_ctx_256b *)pPtr;
    pPtr = NULL;
    pGcmCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* The implementation of CRYPTO_INTERFACE_GCM_init_256b will perform the
     * initialization of the MocSymCtx, however the operator needs to know if
     * you are initializing for encryption or decryption. The original
     * implementation does not care at that time if you are encrypting or
     * decrypting, but the general state management within an operator may
     * reject an inconsistent series of calls (ie initialize for encrypt then
     * call decrypt). So we will store the original request for encrypt/decrypt
     * within the key itself, then pick it up later in the init */
    pGcmCtx->encrypt = encrypt;
    pGcmCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_AES_GCM_CREATE_256B(pGcmCtx, pKeyData, keyLen, encrypt)
  }

exit:

  if (NULL != pPtr)
  {
    DIGI_FREE(&pPtr);
  }
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return pGcmCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_nonce_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_256b *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_NONCE_256B(status, pCtx, pNonce, nonceLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_aad_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_256b *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_AAD_256B(status, pCtx, pAadData, aadDataLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_data_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_256b *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_DATA_256B(status, pCtx, pData, dataLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_ex_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_256b *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_FINAL_EX_256B(status, pCtx, pTag, tagLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_deleteCtx_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER, fStatus = OK;
  gcm_ctx_256b *pGcmCtx = NULL;
  MocSymCtx pSymCtx = NULL;

  if (NULL == ppCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_256b *) *ppCtx;

  status = OK;
  if (NULL == pGcmCtx) /* nothing to free */
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL != pGcmCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType)) )
    {
#ifdef __ENABLE_DIGICERT_TAP__
      status = CRYPTO_INTERFACE_TAP_DeleteAESGCMCtx(pGcmCtx->pMocSymCtx);
#else
      status = ERR_TAP_UNSUPPORTED;
#endif
    }

    /* Make our own copy of the MocSymCtx pointer */
    pSymCtx = pGcmCtx->pMocSymCtx;

    /* Free the outer shell first */
    fStatus = DIGI_FREE((void **)&pGcmCtx);
    if (OK == status)
      status = fStatus;

    /* It is not an error to attempt to free a NULL context */
    if (NULL == pSymCtx)
      goto exit;

    /* Free the inner context */
    fStatus = CRYPTO_freeMocSymCtx(&pSymCtx);
    if (OK == status)
      status = fStatus;

    *ppCtx = NULL;
  }
  else
  {
    MOC_AES_GCM_DELETE_256B(status, ppCtx)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_clone_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_256b *pAesCtx = NULL;
  gcm_ctx_256b *pNewAesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pAesCtx = (gcm_ctx_256b *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pAesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewAesCtx, 1, sizeof(gcm_ctx_256b));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewAesCtx, (void *)pAesCtx, sizeof(gcm_ctx_256b));
    if (OK != status)
      goto exit;

    pNewAesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewAesCtx;
    pNewAesCtx = NULL;

  }
  else
  {
    MOC_AES_GCM_CLONE_256B(status, pCtx, ppNewCtx)
  }

exit:
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewAesCtx)
  {
    DIGI_FREE((void **)&pNewAesCtx);
  }
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen
  )
{
  /* For this call path, the tag is always 16 bytes */
  return CRYPTO_INTERFACE_GCM_init_ex_256b (MOC_SYM(hwAccelCtx)
    pCtx, pNonce, nonceLen, pAaData, aadLen, AES_BLOCK_SIZE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_ex_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte4 tagLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MAesGcmUpdateData gcmUpdateData;
  MocCtx pMocCtx = NULL;
  gcm_ctx_256b *pGcmCtx = NULL;
  ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_256b *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pNonce)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
#ifdef __ENABLE_DIGICERT_TAP__
      status = CRYPTO_INTERFACE_TAP_GCM_init (
        pGcmCtx->pMocSymCtx, pNonce, nonceLen, pAaData, aadLen, tagLen, pGcmCtx->encrypt);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
      status = ERR_INVALID_ARG;
      if (0 == nonceLen)
        goto exit;

      /* Get a reference to the MocCtx from initialization */
      status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
      if (OK != status)
        goto exit;

      /* We assumed encryption to start, check for decryption */
      if (0 == pGcmCtx->encrypt)
        cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

      /* Update the operator with the nonce, additional authentication data,
      * and tag length */
      gcmUpdateData.nonce.pData = pNonce;
      gcmUpdateData.nonce.length = nonceLen;
      gcmUpdateData.aad.pData = pAaData;
      gcmUpdateData.aad.length = aadLen;
      gcmUpdateData.tagLen = tagLen;

      status = CRYPTO_updateSymOperatorData (
        pGcmCtx->pMocSymCtx, pMocCtx, (void *)&gcmUpdateData);
      if (OK != status)
        goto exit;

      /* Initialize the cipher operation */
      status = CRYPTO_cipherInit(pGcmCtx->pMocSymCtx, cipherFlag);
    }
  }
  else
  {
    MOC_AES_GCM_INIT_256B(status, pCtx, pNonce, nonceLen, pAaData, aadLen)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_encrypt_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  ubyte4 dataLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_256b *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_256b *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pData)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pData, dataLen,
        pData, dataLen, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_UPDATE_ENCRYPT_256B(status, pCtx, pData, dataLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_decrypt_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pCipherText,
  ubyte4 cipherTextLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_256b *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_256b *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pCipherText)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT, pCipherText, cipherTextLen,
        pCipherText, cipherTextLen, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_UPDATE_DECRYPT_256B(status, pCtx, pCipherText, cipherTextLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte pTag[/*AES_BLOCK_SIZE*/]
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_256b *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_256b *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pTag)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Call cipherFinal with a NULL input, assuming the output buffer is at least
      * large enough for an AES block */
      status = CRYPTO_cipherFinal (
        pGcmCtx->pMocSymCtx, (ubyte4)pGcmCtx->encrypt, NULL, 0, pTag,
        AES_BLOCK_SIZE, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_FINAL_256B(status, pCtx, pTag)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_cipher_256b (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 tagLen,
  sbyte4 encrypt
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;
  gcm_ctx_256b *pGcmCtx = NULL;
  ubyte4 outLen = 0;
  sbyte4 encryptCopy = -1;
#ifdef __ENABLE_DIGICERT_TAP__
  ubyte *pDecryptedData = NULL;
  ubyte4 decryptedDataLen = 0;
#endif

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_256b *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pData)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    /* Quick check on validity of tagLen */
    status = ERR_AES_BAD_ARG;
    if ( (4 > tagLen) || (16 < tagLen) )
      goto exit;

    /* We assumed encryption to start, check for decryption */
    if (0 == encrypt)
      cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

    encryptCopy = pGcmCtx->encrypt;
    pGcmCtx->encrypt = cipherFlag;

    /* Perform the initialization with the desired tag length */
    status = CRYPTO_INTERFACE_GCM_init_ex_256b (MOC_SYM(hwAccelCtx)
      pCtx, pNonce, nonceLen, pAaData, aadLen, tagLen);
    if (OK != status)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
#ifdef __ENABLE_DIGICERT_TAP__
      /* For decrypt the TAP code wants the full buffer including the tag */
      status = CRYPTO_INTERFACE_TAP_GCM_update (
          pGcmCtx->pMocSymCtx, pData, pGcmCtx->encrypt ? dataLen : dataLen + tagLen, pData, pGcmCtx->encrypt);
        if (OK != status)
          goto exit;

      if (MOC_CIPHER_FLAG_ENCRYPT == cipherFlag)
      {
        status = CRYPTO_INTERFACE_TAP_GCM_final (
          pGcmCtx->pMocSymCtx, pData + dataLen, tagLen, NULL, 0, pGcmCtx->encrypt);
      }
      else
      {
        status = CRYPTO_INTERFACE_TAP_GCM_final (
          pGcmCtx->pMocSymCtx, NULL, 0, &pDecryptedData,
          &decryptedDataLen, pGcmCtx->encrypt);
        if (OK != status)
          goto exit;

        status = DIGI_MEMCPY (
          (void *)pData, (void *)pDecryptedData, decryptedDataLen);
        if (OK != status)
          goto exit;
      }
#else
    return ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, cipherFlag, pData, dataLen,
        pData, dataLen, &outLen);
      if (OK != status)
        goto exit;

      /* If this is encryption, get the tag and place it at the end of the input
      * buffer. If this is decryption, finalize the cipher operation. It is
      * the operator's responsibility to check the tag on a decrypt final. We
      * should only recieve a status code back indicating success or failure */
      if (MOC_CIPHER_FLAG_ENCRYPT == cipherFlag)
      {
        status = CRYPTO_cipherFinal (
          pGcmCtx->pMocSymCtx, cipherFlag, NULL, 0, pData + dataLen,
          AES_BLOCK_SIZE, &outLen);
      }
      else
      {
        status = CRYPTO_cipherFinal (
          pGcmCtx->pMocSymCtx, cipherFlag, pData + dataLen, tagLen, NULL, 0,
          &outLen);
      }
    }


  }
  else
  {
    encryptCopy = pGcmCtx->encrypt;
    MOC_AES_GCM_DO_CIPHER_256B (
      status, pCtx, pNonce, nonceLen, pAaData, aadLen, pData, dataLen, tagLen, encrypt)
  }

exit:

#ifdef __ENABLE_DIGICERT_TAP__
  if (NULL != pDecryptedData)
  {
    DIGI_MEMSET_FREE(&pDecryptedData, decryptedDataLen);
  }
#endif

  if ((NULL != pGcmCtx) && ((TRUE == encryptCopy) || (FALSE == encryptCopy)))
    pGcmCtx->encrypt = encryptCopy;

  return status;
}

#endif /* __ENABLE_DIGICERT_GCM_256B__ */

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_GCM_4K__

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_ex_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte4 tagLen
  );

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_GCM_createCtx_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyData,
  sbyte4 keyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  void *pPtr = NULL;
  MocSymCtx pNewSymCtx = NULL;
  gcm_ctx_4k *pGcmCtx = NULL;

  /* Determine if we have an AES-GCM implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_gcm, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    if ( (0 != keyLen) && (NULL == pKeyData) )
      goto exit;

    /* Create a new MocSymCtx and load the key data in */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, pKeyData, (ubyte4)keyLen, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* We do not want to call init here, we still need the IV and AAD from the
     * init call. Instead we will create an empty object and allocate the GCM
     * shell. When we recieve the IV and AAD in GCM_init_*, we will perform
     * the init. */
    status = DIGI_CALLOC(&pPtr, 1, sizeof(gcm_ctx_4k));
    if (OK != status)
      goto exit;

    pGcmCtx = (gcm_ctx_4k *)pPtr;
    pPtr = NULL;
    pGcmCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* The implementation of CRYPTO_INTERFACE_GCM_init_4k will perform the
     * initialization of the MocSymCtx, however the operator needs to know if
     * you are initializing for encryption or decryption. The original
     * implementation does not care at that time if you are encrypting or
     * decrypting, but the general state management within an operator may
     * reject an inconsistent series of calls (ie initialize for encrypt then
     * call decrypt). So we will store the original request for encrypt/decrypt
     * within the key itself, then pick it up later in the init */
    pGcmCtx->encrypt = encrypt;
    pGcmCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_AES_GCM_CREATE_4K(pGcmCtx, pKeyData, keyLen, encrypt)
  }

exit:

  if (NULL != pPtr)
  {
    DIGI_FREE(&pPtr);
  }
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return pGcmCtx;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_nonce_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_4k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_NONCE_4K(status, pCtx, pNonce, nonceLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_aad_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_4k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_AAD_4K(status, pCtx, pAadData, aadDataLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_data_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_4k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_DATA_4K(status, pCtx, pData, dataLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_ex_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_4k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_FINAL_EX_4K(status, pCtx, pTag, tagLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_deleteCtx_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER, fStatus = OK;
  gcm_ctx_4k *pGcmCtx = NULL;
  MocSymCtx pSymCtx = NULL;

  if (NULL == ppCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_4k *)(*ppCtx);

  /* It is not an error to attempt to free a NULL context */
  status = OK;
  if (NULL == pGcmCtx)
    goto exit;

  /* Determine if we have an AES-GCM implementation */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL != pGcmCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType)) )
    {
#ifdef __ENABLE_DIGICERT_TAP__
      status = CRYPTO_INTERFACE_TAP_DeleteAESGCMCtx(pGcmCtx->pMocSymCtx);
#else
      status = ERR_TAP_UNSUPPORTED;
#endif
    }

    /* Make our own copy of the MocSymCtx pointer */
    pSymCtx = pGcmCtx->pMocSymCtx;

    /* Free the outer shell first */
    fStatus = DIGI_FREE((void **)&pGcmCtx);
    if (OK == status)
      status = fStatus;

    /* It is not an error to attempt to free a NULL context */
    if (NULL == pSymCtx)
      goto exit;

    /* Free the inner context */
    fStatus = CRYPTO_freeMocSymCtx(&pSymCtx);
    if (OK == status)
      status = fStatus;

    *ppCtx = NULL;
  }
  else
  {
    MOC_AES_GCM_DELETE_4K(status, ppCtx)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_clone_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_4k *pAesCtx = NULL;
  gcm_ctx_4k *pNewAesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pAesCtx = (gcm_ctx_4k *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pAesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewAesCtx, 1, sizeof(gcm_ctx_4k));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewAesCtx, (void *)pAesCtx, sizeof(gcm_ctx_4k));
    if (OK != status)
      goto exit;

    pNewAesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewAesCtx;
    pNewAesCtx = NULL;

  }
  else
  {
    MOC_AES_GCM_CLONE_4K(status, pCtx, ppNewCtx)
  }

exit:
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewAesCtx)
  {
    DIGI_FREE((void **)&pNewAesCtx);
  }
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen
  )
{
  /* For this call path, the tag is always 16 bytes */
  return CRYPTO_INTERFACE_GCM_init_ex_4k (MOC_SYM(hwAccelCtx)
    pCtx, pNonce, nonceLen, pAaData, aadLen, AES_BLOCK_SIZE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_ex_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte4 tagLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MAesGcmUpdateData gcmUpdateData;
  MocCtx pMocCtx = NULL;
  gcm_ctx_4k *pGcmCtx = NULL;
  ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_4k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pNonce)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
#ifdef __ENABLE_DIGICERT_TAP__
      status = CRYPTO_INTERFACE_TAP_GCM_init (
        pGcmCtx->pMocSymCtx, pNonce, nonceLen, pAaData, aadLen, tagLen, pGcmCtx->encrypt);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
      status = ERR_INVALID_ARG;
      if (0 == nonceLen)
        goto exit;

      /* Get a reference to the MocCtx from initialization */
      status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
      if (OK != status)
        goto exit;

      /* We assumed encryption to start, check for decryption */
      if (0 == pGcmCtx->encrypt)
        cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

      /* Update the operator with the nonce, additional authentication data,
      * and tag length */
      gcmUpdateData.nonce.pData = pNonce;
      gcmUpdateData.nonce.length = nonceLen;
      gcmUpdateData.aad.pData = pAaData;
      gcmUpdateData.aad.length = aadLen;
      gcmUpdateData.tagLen = tagLen;

      status = CRYPTO_updateSymOperatorData (
        pGcmCtx->pMocSymCtx, pMocCtx, (void *)&gcmUpdateData);
      if (OK != status)
        goto exit;

      /* Initialize the cipher operation */
      status = CRYPTO_cipherInit(pGcmCtx->pMocSymCtx, cipherFlag);
    }
  }
  else
  {
    MOC_AES_GCM_INIT_4K(status, pCtx, pNonce, nonceLen, pAaData, aadLen)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_encrypt_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  ubyte4 dataLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_4k *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_4k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pData)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pData, dataLen,
        pData, dataLen, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_UPDATE_ENCRYPT_4K(status, pCtx, pData, dataLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_decrypt_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pCipherText,
  ubyte4 cipherTextLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_4k *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_4k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pCipherText)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT, pCipherText, cipherTextLen,
        pCipherText, cipherTextLen, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_UPDATE_DECRYPT_4K(status, pCtx, pCipherText, cipherTextLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte pTag[/*AES_BLOCK_SIZE*/]
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_4k *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_4k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pTag)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Call cipherFinal with a NULL input, assuming the output buffer is at least
      * large enough for an AES block */
      status = CRYPTO_cipherFinal (
        pGcmCtx->pMocSymCtx, (ubyte4)pGcmCtx->encrypt, NULL, 0, pTag,
        AES_BLOCK_SIZE, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_FINAL_4K(status, pCtx, pTag)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_cipher_4k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 tagLen,
  sbyte4 encrypt
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;
  gcm_ctx_4k *pGcmCtx = NULL;
  ubyte4 outLen = 0;
  sbyte4 encryptCopy = -1;
#ifdef __ENABLE_DIGICERT_TAP__
  ubyte *pDecryptedData = NULL;
  ubyte4 decryptedDataLen = 0;
#endif

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_4k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pData)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    /* Ensure the tag length is valid. */
    status = ERR_AES_BAD_ARG;
    if ( (4 > tagLen) || (16 < tagLen) )
      goto exit;

    /* We assumed encryption to start, check for decryption */
    if (0 == encrypt)
      cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

    encryptCopy = pGcmCtx->encrypt;
    pGcmCtx->encrypt = cipherFlag;

    /* Perform the initialization with the desired tag length */
    status = CRYPTO_INTERFACE_GCM_init_ex_4k (MOC_SYM(hwAccelCtx)
      pCtx, pNonce, nonceLen, pAaData, aadLen, tagLen);
    if (OK != status)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
#ifdef __ENABLE_DIGICERT_TAP__
      /* For decrypt the TAP code wants the full buffer including the tag */
      status = CRYPTO_INTERFACE_TAP_GCM_update (
          pGcmCtx->pMocSymCtx, pData, pGcmCtx->encrypt ? dataLen : dataLen + tagLen, pData, pGcmCtx->encrypt);
        if (OK != status)
          goto exit;

      if (MOC_CIPHER_FLAG_ENCRYPT == cipherFlag)
      {
        status = CRYPTO_INTERFACE_TAP_GCM_final (
          pGcmCtx->pMocSymCtx, pData + dataLen, tagLen, NULL, 0, pGcmCtx->encrypt);
      }
      else
      {
        status = CRYPTO_INTERFACE_TAP_GCM_final (
          pGcmCtx->pMocSymCtx, NULL, 0, &pDecryptedData,
          &decryptedDataLen, pGcmCtx->encrypt);
        if (OK != status)
          goto exit;

        status = DIGI_MEMCPY (
          (void *)pData, (void *)pDecryptedData, decryptedDataLen);
        if (OK != status)
          goto exit;
      }
#else
    return ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, cipherFlag, pData, dataLen,
        pData, dataLen, &outLen);
      if (OK != status)
        goto exit;

      /* If this is encryption, get the tag and place it at the end of the input
      * buffer. If this is decryption, finalize the cipher operation. It is
      * the operator's responsibility to check the tag on a decrypt final. We
      * should only recieve a status code back indicating success or failure */
      if (MOC_CIPHER_FLAG_ENCRYPT == cipherFlag)
      {
        status = CRYPTO_cipherFinal (
          pGcmCtx->pMocSymCtx, cipherFlag, NULL, 0, pData + dataLen,
          AES_BLOCK_SIZE, &outLen);
      }
      else
      {
        status = CRYPTO_cipherFinal (
          pGcmCtx->pMocSymCtx, cipherFlag, pData + dataLen, tagLen, NULL, 0,
          &outLen);
      }
    }
  }
  else
  {
    encryptCopy = pGcmCtx->encrypt;
    MOC_AES_GCM_DO_CIPHER_4K (
      status, pCtx, pNonce, nonceLen, pAaData, aadLen, pData, dataLen, tagLen, encrypt)
  }

exit:

#ifdef __ENABLE_DIGICERT_TAP__
  if (NULL != pDecryptedData)
  {
    DIGI_MEMSET_FREE(&pDecryptedData, decryptedDataLen);
  }
#endif

  if ((NULL != pGcmCtx) && ((TRUE == encryptCopy) || (FALSE == encryptCopy)))
    pGcmCtx->encrypt = encryptCopy;

  return status;
}

#endif /* __ENABLE_DIGICERT_GCM_4K__ */

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_GCM_64K__

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_ex_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte4 tagLen
  );

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_GCM_createCtx_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyData,
  sbyte4 keyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  void *pPtr = NULL;
  MocSymCtx pNewSymCtx = NULL;
  gcm_ctx_64k *pGcmCtx = NULL;

  /* Determine if we have an AES-GCM implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_gcm, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    if ( (0 != keyLen) && (NULL == pKeyData) )
      goto exit;

    /* Create a new MocSymCtx and load the key data in */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, pKeyData, (ubyte4)keyLen, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* We do not want to call init here, we still need the IV and AAD from the
     * init call. Instead we will create an empty object and allocate the GCM
     * shell. When we recieve the IV and AAD in GCM_init_*, we will perform
     * the init. */
    status = DIGI_CALLOC(&pPtr, 1, sizeof(gcm_ctx_64k));
    if (OK != status)
      goto exit;

    pGcmCtx = (gcm_ctx_64k *)pPtr;
    pPtr = NULL;
    pGcmCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* The implementation of CRYPTO_INTERFACE_GCM_init_64k will perform the
     * initialization of the MocSymCtx, however the operator needs to know if
     * you are initializing for encryption or decryption. The original
     * implementation does not care at that time if you are encrypting or
     * decrypting, but the general state management within an operator may
     * reject an inconsistent series of calls (ie initialize for encrypt then
     * call decrypt). So we will store the original request for encrypt/decrypt
     * within the key itself, then pick it up later in the init */
    pGcmCtx->encrypt = encrypt;
    pGcmCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_AES_GCM_CREATE_64K(pGcmCtx, pKeyData, keyLen, encrypt)
  }

exit:

  if (NULL != pPtr)
  {
    DIGI_FREE(&pPtr);
  }
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return pGcmCtx;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_nonce_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_64k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_NONCE_64K(status, pCtx, pNonce, nonceLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_aad_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_64k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_AAD_64K(status, pCtx, pAadData, aadDataLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_data_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_64k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_UPDATE_DATA_64K(status, pCtx, pData, dataLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_ex_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* If this algorithm is enabled */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == ((gcm_ctx_64k *) pCtx)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_AES_GCM_FINAL_EX_64K(status, pCtx, pTag, tagLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_deleteCtx_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER, fStatus = OK;
  gcm_ctx_64k *pGcmCtx = NULL;
  MocSymCtx pSymCtx = NULL;

  if (NULL == ppCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_64k *)(*ppCtx);

  /* It is not an error to attempt to free a NULL context */
  status = OK;
  if (NULL == pGcmCtx)
    goto exit;

  /* Determine if we have an AES-GCM implementation */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL != pGcmCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType)) )
    {
#ifdef __ENABLE_DIGICERT_TAP__
      status = CRYPTO_INTERFACE_TAP_DeleteAESGCMCtx(pGcmCtx->pMocSymCtx);
#else
      status = ERR_TAP_UNSUPPORTED;
#endif
    }

    /* Make our own copy of the MocSymCtx pointer */
    pSymCtx = pGcmCtx->pMocSymCtx;

    /* Free the outer shell first */
    fStatus = DIGI_FREE((void **)&pGcmCtx);
    if (OK == status)
      status = fStatus;

    /* And set the caller's pointer to NULL too */
    *ppCtx = NULL;

    /* It is not an error to attempt to free a NULL context */
    if (NULL == pSymCtx)
      goto exit;

    /* Free the inner context */
    fStatus = CRYPTO_freeMocSymCtx(&pSymCtx);
    if (OK == status)
      status = fStatus;
  }
  else
  {
    MOC_AES_GCM_DELETE_64K(status, ppCtx)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_clone_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_64k *pAesCtx = NULL;
  gcm_ctx_64k *pNewAesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pAesCtx = (gcm_ctx_64k *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pAesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewAesCtx, 1, sizeof(gcm_ctx_64k));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewAesCtx, (void *)pAesCtx, sizeof(gcm_ctx_64k));
    if (OK != status)
      goto exit;

    pNewAesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewAesCtx;
    pNewAesCtx = NULL;

  }
  else
  {
    MOC_AES_GCM_CLONE_64K(status, pCtx, ppNewCtx)
  }

exit:
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewAesCtx)
  {
    DIGI_FREE((void **)&pNewAesCtx);
  }
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen
  )
{
  /* For this call path, the tag is always 16 bytes */
  return CRYPTO_INTERFACE_GCM_init_ex_64k (MOC_SYM(hwAccelCtx)
    pCtx, pNonce, nonceLen, pAaData, aadLen, AES_BLOCK_SIZE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_init_ex_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte4 tagLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MAesGcmUpdateData gcmUpdateData;
  MocCtx pMocCtx = NULL;
  gcm_ctx_64k *pGcmCtx = NULL;
  ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_64k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pNonce)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
#ifdef __ENABLE_DIGICERT_TAP__
      status = CRYPTO_INTERFACE_TAP_GCM_init (
        pGcmCtx->pMocSymCtx, pNonce, nonceLen, pAaData, aadLen, tagLen, pGcmCtx->encrypt);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
      status = ERR_INVALID_ARG;
      if (0 == nonceLen)
        goto exit;

      /* Get a reference to the MocCtx from initialization */
      status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
      if (OK != status)
        goto exit;

      /* We assumed encryption to start, check for decryption */
      if (0 == pGcmCtx->encrypt)
        cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

      /* Update the operator with the nonce, additional authentication data,
      * and tag length */
      gcmUpdateData.nonce.pData = pNonce;
      gcmUpdateData.nonce.length = nonceLen;
      gcmUpdateData.aad.pData = pAaData;
      gcmUpdateData.aad.length = aadLen;
      gcmUpdateData.tagLen = tagLen;

      status = CRYPTO_updateSymOperatorData (
        pGcmCtx->pMocSymCtx, pMocCtx, (void *)&gcmUpdateData);
      if (OK != status)
        goto exit;

      /* Initialize the cipher operation */
      status = CRYPTO_cipherInit(pGcmCtx->pMocSymCtx, cipherFlag);
    }
  }
  else
  {
    MOC_AES_GCM_INIT_64K(status, pCtx, pNonce, nonceLen, pAaData, aadLen)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_encrypt_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  ubyte4 dataLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_64k *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_64k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pData)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pData, dataLen,
        pData, dataLen, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_UPDATE_ENCRYPT_64K(status, pCtx, pData, dataLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_update_decrypt_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pCipherText,
  ubyte4 cipherTextLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_64k *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_64k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pCipherText)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT, pCipherText, cipherTextLen,
        pCipherText, cipherTextLen, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_UPDATE_DECRYPT_64K(status, pCtx, pCipherText, cipherTextLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_final_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte pTag[/*AES_BLOCK_SIZE*/]
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  gcm_ctx_64k *pGcmCtx = NULL;
  ubyte4 outLen = 0;

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_64k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pTag)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
      /* TAP-GCM does not support multi-part */
      return ERR_TAP_UNSUPPORTED;
    }
    else
    {
      /* Call cipherFinal with a NULL input, assuming the output buffer is at least
      * large enough for an AES block */
      status = CRYPTO_cipherFinal (
        pGcmCtx->pMocSymCtx, (ubyte4)pGcmCtx->encrypt, NULL, 0, pTag,
        AES_BLOCK_SIZE, &outLen);
    }
  }
  else
  {
    MOC_AES_GCM_FINAL_64K(status, pCtx, pTag)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_GCM_cipher_64k (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAaData,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 tagLen,
  sbyte4 encrypt
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;
  gcm_ctx_64k *pGcmCtx = NULL;
  ubyte4 outLen = 0;
  sbyte4 encryptCopy = -1;
#ifdef __ENABLE_DIGICERT_TAP__
  ubyte *pDecryptedData = NULL;
  ubyte4 decryptedDataLen = 0;
#endif

  if (NULL == pCtx)
    goto exit;

  pGcmCtx = (gcm_ctx_64k *)pCtx;

  /* If this algorithm is enabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pGcmCtx->enabled)
  {
    if (NULL == pData)
      goto exit;

    /* Ensure we have a MocSymCtx to work with */
    if (NULL == pGcmCtx->pMocSymCtx)
      goto exit;

    /* Ensure the tag length is valid. */
    status = ERR_AES_BAD_ARG;
    if ( (4 > tagLen) || (16 < tagLen) )
      goto exit;

    /* We assumed encryption to start, check for decryption */
    if (0 == encrypt)
      cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

    encryptCopy = pGcmCtx->encrypt;
    pGcmCtx->encrypt = cipherFlag;

    /* Perform the initialization with the desired tag length */
    status = CRYPTO_INTERFACE_GCM_init_ex_64k (MOC_SYM(hwAccelCtx)
      pCtx, pNonce, nonceLen, pAaData, aadLen, tagLen);
    if (OK != status)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
    {
#ifdef __ENABLE_DIGICERT_TAP__
      /* For decrypt the TAP code wants the full buffer including the tag */
      status = CRYPTO_INTERFACE_TAP_GCM_update (
          pGcmCtx->pMocSymCtx, pData, pGcmCtx->encrypt ? dataLen : dataLen + tagLen, pData, pGcmCtx->encrypt);
        if (OK != status)
          goto exit;

      if (MOC_CIPHER_FLAG_ENCRYPT == cipherFlag)
      {
        status = CRYPTO_INTERFACE_TAP_GCM_final (
          pGcmCtx->pMocSymCtx, pData + dataLen, tagLen, NULL, 0, pGcmCtx->encrypt);
      }
      else
      {
        status = CRYPTO_INTERFACE_TAP_GCM_final (
          pGcmCtx->pMocSymCtx, NULL, 0, &pDecryptedData,
          &decryptedDataLen, pGcmCtx->encrypt);
        if (OK != status)
          goto exit;

        status = DIGI_MEMCPY (
          (void *)pData, (void *)pDecryptedData, decryptedDataLen);
        if (OK != status)
          goto exit;
      }
#else
    return ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
      /* Perform the update in place by passing the same buffer for input
      * and output */
      status = CRYPTO_cipherUpdate (
        pGcmCtx->pMocSymCtx, cipherFlag, pData, dataLen,
        pData, dataLen, &outLen);

      /* If this is encryption, get the tag and place it at the end of the input
      * buffer. If this is decryption, finalize the cipher operation. It is
      * the operator's responsibility to check the tag on a decrypt final. The
      * operator will check the tag internally if the output buffer is NULL
      * otherwise it will return the tag in the output buffer. Since the tag
      * is provided by the caller, pass in NULL for the output buffer so the
      * tag will be checked internally. We  should only recieve a status code
      * back indicating success or failure */
      if (MOC_CIPHER_FLAG_ENCRYPT == cipherFlag)
      {
        status = CRYPTO_cipherFinal (
          pGcmCtx->pMocSymCtx, cipherFlag, NULL, 0, pData + dataLen,
          AES_BLOCK_SIZE, &outLen);
      }
      else
      {
        status = CRYPTO_cipherFinal (
          pGcmCtx->pMocSymCtx, cipherFlag, pData + dataLen, tagLen, NULL, 0,
          &outLen);
      }
    }
  }
  else
  {
    encryptCopy = pGcmCtx->encrypt;
    MOC_AES_GCM_DO_CIPHER_64K (
      status, pCtx, pNonce, nonceLen, pAaData, aadLen, pData, dataLen, tagLen, encrypt)
  }

exit:

#ifdef __ENABLE_DIGICERT_TAP__
  if (NULL != pDecryptedData)
  {
    DIGI_MEMSET_FREE(&pDecryptedData, decryptedDataLen);
  }
#endif

  if ((NULL != pGcmCtx) && ((TRUE == encryptCopy) || (FALSE == encryptCopy)))
    pGcmCtx->encrypt = encryptCopy;

  return status;
}

#endif /* __ENABLE_DIGICERT_GCM_64K__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_newCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppNewCtx,
  ubyte4 tableSizeMode, 
  ubyte *pKeyData, 
  sbyte4 keyDataLen,
  sbyte4 encrypt)
{
  MSTATUS status = ERR_NULL_POINTER;
  AES_GCM_CTX *pNewCtx = NULL;
  BulkCtx pTblCtx = NULL;
  ubyte4 algoStatus, index;
  MocSymCtx pNewSymCtx = NULL;

  if (NULL == ppNewCtx)
    goto exit;

  status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(AES_GCM_CTX));
  if (OK != status)
    goto exit;

  switch (tableSizeMode)
  {
#ifdef __ENABLE_DIGICERT_GCM_256B__
    case GCM_MODE_256B:

      pTblCtx = CRYPTO_INTERFACE_GCM_createCtx_256b(MOC_SYM(hwAccelCtx) pKeyData, keyDataLen, encrypt);
      if (NULL == pTblCtx)
      {
          status = ERR_MEM_ALLOC_FAIL;
          goto exit;
      }

      pNewCtx->pTblCtx = pTblCtx;
      pNewCtx->tableSize = GCM_MODE_256B;
      break;

#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    case GCM_MODE_4K:

      pTblCtx = CRYPTO_INTERFACE_GCM_createCtx_4k(MOC_SYM(hwAccelCtx) pKeyData, keyDataLen, encrypt);
      if (NULL == pTblCtx)
      {
          status = ERR_MEM_ALLOC_FAIL;
          goto exit;
      }

      pNewCtx->pTblCtx = pTblCtx;
      pNewCtx->tableSize = GCM_MODE_4K;
      break;
    
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    case GCM_MODE_64K:

      pTblCtx = CRYPTO_INTERFACE_GCM_createCtx_64k(MOC_SYM(hwAccelCtx) pKeyData, keyDataLen, encrypt);
      if (NULL == pTblCtx)
      {
          status = ERR_MEM_ALLOC_FAIL;
          goto exit;
      }

      pNewCtx->pTblCtx =  pTblCtx;
      pNewCtx->tableSize = GCM_MODE_64K;
      break;
    
#endif
    case GCM_MODE_GENERAL:

      /* make sure we have an operator available */
      status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_gcm, &algoStatus, &index);
      if (OK != status)
        goto exit;

      if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
      {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
        goto exit;
      }
  
      if ( 0 != keyDataLen && NULL == pKeyData )
      {
        status = ERR_NULL_POINTER;
        goto exit;
      }

      /* Create a new MocSymCtx and load the key data in */
      status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, pKeyData, (ubyte4) keyDataLen, &pNewSymCtx);
      if (OK != status)
        goto exit;

      pNewCtx->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
      pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
      /* pNewCtx->tablesize = GCM_MODE_GENERAL, ie 0, already */
      break;

    default:

      status = ERR_INVALID_ARG;
      goto exit;
  }

  *ppNewCtx = pNewCtx; pNewCtx = NULL;

exit:

  if (NULL != pNewSymCtx)
  {
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  /* No need to free pNewCtx->pTblCtx since its allocation was last step that can fail */

  if (NULL != pNewCtx)
  {
    (void) DIGI_FREE((void **) &pNewCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_encrypt(
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,      
  ubyte *pNonce,
  ubyte4 *pNonceLen,
  intBoolean *pWasNonceUsed,
  ubyte *pAad,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 tagLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  AES_GCM_CTX *pGcmCtx = (AES_GCM_CTX *) pCtx;
  MAesGcmUpdateData gcmUpdateData = {0};
  MocCtx pMocCtx = NULL;

  if (NULL == pGcmCtx || NULL == pNonceLen || NULL == pWasNonceUsed)
    goto exit;

  switch (pGcmCtx->tableSize)
  {
#ifdef __ENABLE_DIGICERT_GCM_256B__
    case GCM_MODE_256B:

      status = CRYPTO_INTERFACE_GCM_cipher_256b(MOC_SYM(hwAccelCtx) pGcmCtx->pTblCtx, pNonce, *pNonceLen, pAad, aadLen, pData, dataLen, tagLen, 1);
      if (OK != status)
        goto exit;

      *pWasNonceUsed = TRUE;  /* CRYPTO_INTERFACE_GCM_GCM_cipher_<size> implementations are required to use the nonce */ 
      break;

#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    case GCM_MODE_4K:

      status = CRYPTO_INTERFACE_GCM_cipher_4k(MOC_SYM(hwAccelCtx) pGcmCtx->pTblCtx, pNonce, *pNonceLen, pAad, aadLen, pData, dataLen, tagLen, 1);
      if (OK != status)
        goto exit;

      *pWasNonceUsed = TRUE;
      break;
    
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    case GCM_MODE_64K:

      status = CRYPTO_INTERFACE_GCM_cipher_64k(MOC_SYM(hwAccelCtx) pGcmCtx->pTblCtx, pNonce, *pNonceLen, pAad, aadLen, pData, dataLen, tagLen, 1);
      if (OK != status)
        goto exit;

      *pWasNonceUsed = TRUE;
      break;
    
#endif
    case GCM_MODE_GENERAL:

      /* make sure its enabled */
      status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
      if (CRYPTO_INTERFACE_ALGO_ENABLED != pGcmCtx->enabled)
        goto exit;
      
      status = ERR_NULL_POINTER;
      if (NULL == pData || NULL == pNonce || NULL == pGcmCtx->pMocSymCtx)
        goto exit;

      if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
      {
#ifdef __ENABLE_DIGICERT_TAP__
        status = CRYPTO_INTERFACE_TAP_GCM_encrypt(pGcmCtx->pMocSymCtx, pNonce, pNonceLen, pWasNonceUsed, pAad, aadLen, pData, dataLen, tagLen);
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
      }
      else
      {
        ubyte4 outLen = 0;

        /* Quick check on validity of other args */
        status = ERR_AES_BAD_ARG;
        if ( (4 > tagLen) || (16 < tagLen) )
          goto exit;

        status = ERR_INVALID_ARG;
        if (0 == *pNonceLen)
          goto exit;

        /* Get a reference to the MocCtx from initialization */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
          goto exit;

        /* Update the operator with the nonce, additional authentication data and tag length */
        gcmUpdateData.nonce.pData = pNonce;
        gcmUpdateData.nonce.length = *pNonceLen;
        gcmUpdateData.aad.pData = pAad;
        gcmUpdateData.aad.length = aadLen;
        gcmUpdateData.tagLen = tagLen;

        status = CRYPTO_updateSymOperatorData (pGcmCtx->pMocSymCtx, pMocCtx, (void *)&gcmUpdateData);
        if (OK != status)
          goto exit;

        /* Initialize the cipher operation */
        status = CRYPTO_cipherInit(pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT);
        if (OK != status)
          goto exit;
      
        /* Perform the update in place by passing the same buffer for input and output */
        status = CRYPTO_cipherUpdate(pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pData, dataLen, pData, dataLen, &outLen);
        if (OK != status)
          goto exit;

        /* We ignore tagLen and assume we have 16 bytes for the tag */
        status = CRYPTO_cipherFinal(pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, NULL, 0, pData + dataLen, tagLen, &outLen);
        if (OK != status)
          goto exit;

        *pWasNonceUsed = TRUE;
      }
      break;

    default:

      status = ERR_INVALID_ARG;
      goto exit;
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_decrypt(
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAad,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 tagLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  AES_GCM_CTX *pGcmCtx = (AES_GCM_CTX *) pCtx;
  MAesGcmUpdateData gcmUpdateData = {0};
  MocCtx pMocCtx = NULL;

  if (NULL == pGcmCtx)
    goto exit;

  switch (pGcmCtx->tableSize)
  {
#ifdef __ENABLE_DIGICERT_GCM_256B__
    case GCM_MODE_256B:

      status = CRYPTO_INTERFACE_GCM_cipher_256b(MOC_SYM(hwAccelCtx) pGcmCtx->pTblCtx, pNonce, nonceLen, pAad, aadLen, pData, dataLen, tagLen, 0);
      break;

#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    case GCM_MODE_4K:

      status = CRYPTO_INTERFACE_GCM_cipher_4k(MOC_SYM(hwAccelCtx) pGcmCtx->pTblCtx, pNonce, nonceLen, pAad, aadLen, pData, dataLen, tagLen, 0);
      break;
    
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    case GCM_MODE_64K:

      status = CRYPTO_INTERFACE_GCM_cipher_64k(MOC_SYM(hwAccelCtx) pGcmCtx->pTblCtx, pNonce, nonceLen, pAad, aadLen, pData, dataLen, tagLen, 0);
      break;
    
#endif
    case GCM_MODE_GENERAL:

      /* make sure its enabled */
      status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
      if (CRYPTO_INTERFACE_ALGO_ENABLED != pGcmCtx->enabled)
        goto exit;
      
      status = ERR_NULL_POINTER;
      if (NULL == pData || NULL == pNonce || NULL == pGcmCtx->pMocSymCtx)
        goto exit;

      if (0 != (MOC_LOCAL_TYPE_TAP & pGcmCtx->pMocSymCtx->localType))
      {
#ifdef __ENABLE_DIGICERT_TAP__
        status = CRYPTO_INTERFACE_TAP_GCM_decrypt(pGcmCtx->pMocSymCtx, pNonce, nonceLen, pAad, aadLen, pData, dataLen, tagLen);
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
      }
      else
      {
        ubyte4 outLen = 0;

        /* Quick check on validity of other args */
        status = ERR_AES_BAD_ARG;
        if ( (4 > tagLen) || (16 < tagLen) )
          goto exit;

        status = ERR_INVALID_ARG;
        if (0 == nonceLen)
          goto exit;

        /* Get a reference to the MocCtx from initialization */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
          goto exit;

        /* Update the operator with the nonce, additional authentication data and tag length */
        gcmUpdateData.nonce.pData = pNonce;
        gcmUpdateData.nonce.length = nonceLen;
        gcmUpdateData.aad.pData = pAad;
        gcmUpdateData.aad.length = aadLen;
        gcmUpdateData.tagLen = tagLen;

        status = CRYPTO_updateSymOperatorData (pGcmCtx->pMocSymCtx, pMocCtx, (void *)&gcmUpdateData);
        if (OK != status)
          goto exit;

        /* Initialize the cipher operation */
        status = CRYPTO_cipherInit(pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT);
        if (OK != status)
          goto exit;
      
        /* Perform the update in place by passing the same buffer for input and output */
        status = CRYPTO_cipherUpdate(pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT, pData, dataLen, pData, dataLen, &outLen);
        if (OK != status)
          goto exit;

        /* Verify the tag */
        status = CRYPTO_cipherFinal(pGcmCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT, pData + dataLen, tagLen, NULL, 0, &outLen);
        if (OK != status)
          goto exit;
      }
      break;

    default:

      status = ERR_INVALID_ARG;
      goto exit;
  }

exit:

  return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_GCM_deleteCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
  MSTATUS status = ERR_NULL_POINTER;
  MSTATUS fstatus = OK;
  AES_GCM_CTX *pGcmCtx = NULL;

  if (NULL == ppCtx)
    goto exit;

  status = OK; /* OK no-op if nothing to free */
  if (NULL == *ppCtx)
    goto exit;

  pGcmCtx = (AES_GCM_CTX *) *ppCtx;
  
  switch (pGcmCtx->tableSize)
  {
#ifdef __ENABLE_DIGICERT_GCM_256B__
    case GCM_MODE_256B:

      status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(MOC_SYM(hwAccelCtx) &pGcmCtx->pTblCtx);
      break;

#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    case GCM_MODE_4K:

      status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(MOC_SYM(hwAccelCtx) &pGcmCtx->pTblCtx);
      break;
    
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    case GCM_MODE_64K:

      status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(MOC_SYM(hwAccelCtx) &pGcmCtx->pTblCtx);
      break;
    
#endif
    case GCM_MODE_GENERAL:

      status = CRYPTO_freeMocSymCtx(&pGcmCtx->pMocSymCtx);
      break;

    default:

      status = ERR_INVALID_ARG;
      break;
  }

  fstatus = DIGI_FREE(ppCtx);
  if (OK == status)
    status = fstatus;

exit:

  return status;
}
#endif
