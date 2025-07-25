
/*
 * nist_rng.h
 *
 * Implementation of the RNGs described in NIST 800-90
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

/*! \file nist_rng_ex.h NIST RNG developer API header.
This header file contains definitions, enumerations, structures, and function
declarations used for NIST RNG constructions as described in NIST 800-90.

\since 3.0.6
\version 5.0.5 and later

! Flags
No flag definitions are required to use this file.

! External Functions
*/

#ifndef __NIST_RNG_CTR_EX_HEADER__
#define __NIST_RNG_CTR_EX_HEADER__

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_nist_ctr_drbg_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generates a "secret" which consist of the internal state, ie the V and key,
 * followed by the deterministic random bits that can be generated by that state.
 *
 * @param pContext           Pointer to a randomContext created with no derivation function.
 * @param pAdditionalInput   Additional input. This is optional and may be NULL.
 * @param additionalInputLen The length of the additional input in bytes.
 * @param pSecret            Pointer to a buffer that will hold the resulting secret.
 * @param secretLen          The length of the secret you desire. This must be at least
                             the length of the key plus the output length.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_generateSecret(MOC_SYM(hwAccelDescr hwAccelCtx)
                                               randomContext* pContext,
                                               ubyte *pAdditionalInput,
                                               ubyte4 additionalInputLen,
                                               ubyte *pSecret,
                                               ubyte4 secretLen);

/**
 * Sets the state of a context to the state within the secret passed in. The
 * rest of the secret will be verified that it contains the deterministic bits
 * that can be generated from that state and the state will be incrememted to
 * the next state.
 *
 * @param pContext           Pointer to a randomContext created with no derivation function.
 * @param pAdditionalInput   Additional input. This is optional and may be NULL.
 * @param additionalInputLen The length of the additional input in bytes.
 * @param pSecret            Pointer to a buffer containing a secret.
 * @param secretLen          The length of the pSecret buffer in bytes.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS NIST_CTRDRBG_setStateFromSecret(MOC_SYM(hwAccelDescr hwAccelCtx)
                                                   randomContext* pContext,
                                                   ubyte *pAdditionalInput,
                                                   ubyte4 additionalInputLen,
                                                   ubyte *pSecret,
                                                   ubyte4 secretLen);

#ifdef __cplusplus
}
#endif

#endif /* __NIST_RNG_CTR_EX_HEADER__ */
