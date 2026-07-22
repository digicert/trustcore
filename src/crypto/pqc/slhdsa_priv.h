/*
 * slhdsa_priv.h
 *
 * SLH DSA Internal Functions for NIST Testing
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


#ifndef __SLHDSA_PRIV_HEADER__
#define __SLHDSA_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "../../crypto/hw_accel.h"
#include "../../crypto/pqc/slhdsa.h"

/* Special 'internal' functions referenced in ACVP test document
 * Make sure this list is in *sync* with the one in 'slhdsa.c'
 */
#define SLHDSA_KEYGEN_INTERNAL_F_ID   1
#define SLHDSA_SIGN_INTERNAL_F_ID     2
#define SLHDSA_VERIFY_INTERNAL_F_ID   3
#define SLHDSA_GET_OLD_CTX_F_ID       4
#define SLHDSA_GET_OLD_N_F_ID         5
#define SLHDSA_TRIGGER_FAIL_F_ID      6

typedef MSTATUS (slhdsa_keygen_internal_f)(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, ubyte *pBuf);
typedef MSTATUS (slhdsa_sign_internal_f)(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, ubyte *pSk,
				  ubyte *pDataPrefix, ubyte4 dataPrefixLen,
				  ubyte *pMsgRep, ubyte4 msgRepLen, ubyte *pSig);
typedef MSTATUS (slhdsa_verify_internal_f)(MOC_HASH(hwAccelDescr hwAccelCtx) const SlhdsaCtx *pCtx, ubyte *pPk,
				    ubyte *pDataPrefix, ubyte4 dataPrefixLen, ubyte *pMsgRep,
				    ubyte4 msgRepLen, ubyte *pSig, sbyte4 sigLen, ubyte4 *pVerifyStatus);
typedef const SlhdsaCtx* (slhdsa_get_old_ctx_f)(SLHDSAType type);
typedef ubyte4 (slhdsa_get_old_n_f)(const SlhdsaCtx *pCtx);

MOC_EXTERN const FIPS_entry_fct* SLHDSA_getPrivileged();

#ifdef __cplusplus
}
#endif

#endif /* __SLHDSA_PRIV_HEADER__ */
