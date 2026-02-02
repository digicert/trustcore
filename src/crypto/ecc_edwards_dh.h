/*
 * ecc_edwards_dh.h
 *
 * Header for Edward's Curve Diffie-Hellman operations.
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

/**
 * @file       ecc_edwards_dh.h
 *
 * @brief      Header for Edward's curve Diffie-Hellman related methods.
 *
 * @details    Documentation file for Edward's curve Diffie-Hellman related methods.
 *
 * @flags      To enable the methods in this file one must define
 *             + \c \__ENABLE_DIGICERT_ECC__
 *             and at least one or more of the following flags
 *             + \c \__ENABLE_DIGICERT_ECC_EDDH_25519__
 *             + \c \__ENABLE_DIGICERT_ECC_EDDH_448__
 *
 * @filedoc    ecc_edwards_dh.h
 */

/*------------------------------------------------------------------*/

#ifndef __ECC_EDWARDS_DH_HEADER__
#define __ECC_EDWARDS_DH_HEADER__

#include "../crypto/ecc_edwards_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief    Generates a Edward's form Diffie-Hellman shared secret.
 *
 * @details  Generates a Edward's form Diffie-Hellman shared secret from an \c edECCKey form
 *           private key and the other party's public key. A buffer will be allocated and
 *           to hold the generated shared secret and be sure to FREE this buffer when done with it.
 *
 * @param pPrivateKey            Pointer to our private key.
 * @param pOtherPartysPublicKey  Buffer holding the other party's public key.
 * @param publicKeyLen           The length of the other party's public key in bytes.
 *                               This must be 32 for curve25519 and 56 for curve448.
 * @param ppSharedSecret         Pointer to a buffer that will be allocated and filled
 *                               with the resulting shared secret.
 * @param pSharedSecretLen       Contents will be set to the number of bytes in the allocated buffer.
 * @param pExtCtx                An extended context reserved for future use.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS edDH_GenerateSharedSecret(MOC_ECC(hwAccelDescr hwAccelCtx) edECCKey *pPrivateKey, ubyte *pOtherPartysPublicKey, ubyte4 publicKeyLen,
                                             ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen, void *pExtCtx);

#ifdef __cplusplus
}
#endif

#endif /* __ECC_EDWARDS_DH_HEADER__ */
