/*
 * nist_rng_priv.h
 *
 * DRBG Internal Functions for NIST Testing
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

#ifndef __NIST_RNG_PRIV_HEADER__
#define __NIST_RNG_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* For KAT and ACVP tests only. Do not call from other applications! */
MOC_EXTERN MSTATUS
NIST_CTRDRBG_newContext_internal( MOC_SYM(hwAccelDescr hwAccelCtx)
                            randomContext **ppNewContext,
                            const ubyte* entropyInput,
                            ubyte4 keyLenBytes, ubyte4 outLenBytes,
                            const ubyte* personalization,
                            ubyte4 personalizationLen);

MOC_EXTERN MSTATUS
NIST_CTRDRBG_newDFContext_internal( MOC_SYM(hwAccelDescr hwAccelCtx)
                            randomContext **ppNewContext,
                            ubyte4 keyLenBytes, ubyte4 outLenBytes,
                            const ubyte* entropyInput,
                            ubyte4 entropyInputLen,
                            const ubyte* nonce,
                            ubyte4 nonceLen,
                            const ubyte* personalization,
                            ubyte4 personalizationLen);

MOC_EXTERN MSTATUS
NIST_CTRDRBG_reseed_internal(MOC_SYM(hwAccelDescr hwAccelCtx)
                            randomContext *pContext,
                            const ubyte* entropyInput,
                            ubyte4 entropyInputLen,
                            const ubyte* additionalInput,
                            ubyte4 additionalInputLen);

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#define DRBG_TRIGGER_FAIL_F_ID 1
#define DRBG_RESET_FAIL_F_ID   2

MOC_EXTERN const FIPS_entry_fct* DRBG_getPrivileged(void);
#endif

#ifdef __cplusplus
}
#endif
#endif /* __NIST_RNG_PRIV_HEADER__ */
