 /*
 * crypto_interface_ecc_eg.c
 *
 * Cryptographic Interface for ECEG.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_ELGAMAL_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/primeec_eg.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_ELGAMAL__))

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__))
#define MOC_ECEG_INIT(_status, _pCtx, _pKey, _direction, _rngFun, _pRngArg, _pExtCtx) \
    _status = ECEG_init(MOC_ECC(hwAccelCtx) _pCtx, _pKey, _direction, _rngFun, _pRngArg, _pExtCtx);
#else
#define MOC_ECEG_INIT(_status, _pCtx, _pKey, _direction, _rngFun, _pRngArg, _pExtCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__))
#define MOC_ECEG_UPDATE(_status, _pCtx, _pInputData, _inputDataLen, _pOutputData, _outputDataBufferLen, _pBytesWritten, _pExtCtx) \
    _status = ECEG_update(MOC_ECC(hwAccelCtx) _pCtx, _pInputData, _inputDataLen, _pOutputData, _outputDataBufferLen, _pBytesWritten, _pExtCtx);
#else
#define MOC_ECEG_UPDATE(_status, _pCtx, _pInputData, _inputDataLen, _pOutputData, _outputDataBufferLen, _pBytesWritten, _pExtCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__))
#define MOC_ECEG_FINAL(_status, _pCtx, _pExtCtx) \
    _status = ECEG_final(MOC_ECC(hwAccelCtx) _pCtx, _pExtCtx);
#else
#define MOC_ECEG_FINAL(_status, _pCtx, _pExtCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__))
#define MOC_ECEG_ENCRYPT(_status, _pPublicKey, _rngFun, _pRngArg, _pPlaintext, _plaintextLen, _ppCiphertext, _pCiphertextLen, _pExtCtx) \
    _status = ECEG_encrypt(MOC_ECC(hwAccelCtx) _pPublicKey, _rngFun, _pRngArg, _pPlaintext, _plaintextLen, _ppCiphertext, _pCiphertextLen, _pExtCtx);
#else
#define MOC_ECEG_ENCRYPT(_status, _pPublicKey, _rngFun, _pRngArg, _pPlaintext, _plaintextLen, _ppCiphertext, _pCiphertextLen, _pExtCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

 /*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__))
#define MOC_ECEG_DECRYPT(_status, _pPrivateKey, _pCiphertext, _ciphertextLen, _ppPlaintext, _pPlaintextLen, _pExtCtx) \
    _status = ECEG_decrypt(MOC_ECC(hwAccelCtx) _pPrivateKey, _pCiphertext, _ciphertextLen, _ppPlaintext, _pPlaintextLen, _pExtCtx);
#else
#define MOC_ECEG_DECRYPT(_status, _pPrivateKey, _pCiphertext, _ciphertextLen, _ppPlaintext, _pPlaintextLen, _pExtCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

 /*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__))
#define MOC_ECEG_ENCRYPT_V1P5(_status, _pPublicKey, _rngFun, _pRngArg, _pPlaintext, _plaintextLen, _pCiphertext, _pExtCtx) \
    _status = ECEG_encryptPKCSv1p5(MOC_ECC(hwAccelCtx) _pPublicKey, _rngFun, _pRngArg, _pPlaintext, _plaintextLen, _pCiphertext, _pExtCtx);
#else
#define MOC_ECEG_ENCRYPT_V1P5(_status, _pPublicKey, _rngFun, _pRngArg, _pPlaintext, _plaintextLen, _pCiphertext, _pExtCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

 /*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__))
#define MOC_ECEG_DECRYPT_V1P5(_status, _pPrivateKey, _pCiphertext, _ciphertextLen, _pPlaintext, _pExtCtx) \
    _status = ECEG_decryptPKCSv1p5(MOC_ECC(hwAccelCtx) _pPrivateKey, _pCiphertext, _ciphertextLen, _pPlaintext, _pExtCtx);
#else
#define MOC_ECEG_DECRYPT_V1P5(_status, _pPrivateKey, _pCiphertext, _ciphertextLen, _pPlaintext, _pExtCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

 /*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECEG_init(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, ECCKey *pKey, ubyte direction, RNGFun rngFun, void *pRngArg, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pKey)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_ECEG_INIT(status, pCtx, pKey, direction, rngFun, pRngArg, pExtCtx)
  }

exit:
  
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECEG_update(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, ubyte *pInputData, ubyte4 inputDataLen, ubyte *pOutputData, ubyte4 outputDataBufferLen, ubyte4 *pBytesWritten, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx || NULL == pCtx->pKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_ECEG_UPDATE(status, pCtx, pInputData, inputDataLen, pOutputData, outputDataBufferLen, pBytesWritten, pExtCtx)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECEG_final(MOC_ECC(hwAccelDescr hwAccelCtx) ECEG_CTX *pCtx, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx || NULL == pCtx->pKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->pKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_ECEG_FINAL(status, pCtx, pExtCtx)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECEG_encrypt(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPublicKey, RNGFun rngFun, void *pRngArg, ubyte *pPlaintext, ubyte4 plaintextLen, ubyte **ppCiphertext, ubyte4 *pCiphertextLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pPublicKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPublicKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_ECEG_ENCRYPT(status, pPublicKey, rngFun, pRngArg, pPlaintext, plaintextLen, ppCiphertext, pCiphertextLen, pExtCtx)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECEG_decrypt(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPrivateKey, ubyte *pCiphertext, ubyte4 ciphertextLen, ubyte **ppPlaintext, ubyte4 *pPlaintextLen, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pPrivateKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivateKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_ECEG_DECRYPT(status, pPrivateKey, pCiphertext, ciphertextLen, ppPlaintext, pPlaintextLen, pExtCtx)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECEG_encryptPKCSv1p5(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPublicKey, RNGFun rngFun, void *pRngArg, ubyte *pPlaintext, ubyte4 plaintextLen, ubyte *pCiphertext, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pPublicKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPublicKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_ECEG_ENCRYPT_V1P5(status, pPublicKey, rngFun, pRngArg, pPlaintext, plaintextLen, pCiphertext, pExtCtx)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECEG_decryptPKCSv1p5(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pPrivateKey, ubyte *pCiphertext, ubyte4 ciphertextLen, ubyte *pPlaintext, void *pExtCtx)
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pPrivateKey)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivateKey->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_ECEG_DECRYPT_V1P5(status, pPrivateKey, pCiphertext, ciphertextLen, pPlaintext, pExtCtx)
  }

exit:

  return status;
}
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_ELGAMAL__)) */
