/*
 * mldsa_priv.h
 *
 * ML DSA Internal Functions for NIST Testing
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


#ifndef __MLDSA_PRIV_HEADER__
#define __MLDSA_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "../../crypto/hw_accel.h"
#include "../../crypto/pqc/mldsa.h"

/* Special 'internal' functions referenced in ACVP test document
 * Make sure this list is in *sync* with the one in 'mldsa.c'
 */
#define MLDSA_KEYGEN_INTERNAL_F_ID  1
#define MLDSA_SIGN_INTERNAL_F_ID    2
#define MLDSA_VERIFY_INTERNAL_F_ID  3
#define MLDSA_TRIGGER_FAIL_F_ID     4

typedef MSTATUS (mldsa_keygen_internal_f)(MLDSACtx *ctx, uint8_t *xi, uint8_t *sk, uint8_t *pk);
typedef MSTATUS (mldsa_sign_internal_f)(MLDSACtx *ctx, ubyte *pMu, uint8_t *msg, size_t msgLen,
				  uint8_t *rnd, uint8_t *sig);
typedef MSTATUS (mldsa_verify_internal_f)(MLDSACtx *ctx, ubyte *pMu, uint8_t *msg, size_t msgLen,
				    uint8_t *sig, uint32_t *verifyStatus);

MOC_EXTERN const FIPS_entry_fct* MLDSA_getPrivileged();

#ifdef __cplusplus
}
#endif

#endif /* __MLDSA_PRIV_HEADER__ */
