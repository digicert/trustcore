/*
 * mlkem_priv.h
 *
 * ML KEM Internal Functions for NIST Testing
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


#ifndef __MLKEM_PRIV_HEADER__
#define __MLKEM_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "../../crypto/hw_accel.h"
#include "../../crypto/pqc/mlkem.h"

/* Special 'internal' functions referenced in ACVP test document
 * Make sure this list is in *sync* with the one in 'mlkem.c'
 */

#define MLKEM_KEY_VALIDITY_CHECK_F_ID 1
#define MLKEM_KEY_HASH_CHECK_F_ID     2
#define MLKEM_KEYGEN_INTERNAL_F_ID    3
#define MLKEM_ENCAPS_INTERNAL_F_ID    4
#define MLKEM_DECAPS_INTERNAL_F_ID    5
#define MLKEM_GET_OLD_CTX_F_ID        6
#define MLKEM_GET_OLD_CIPHER_LEN_F_ID 7
#define MLKEM_GET_OLD_DK_PUB_LEN_F_ID 8
#define MLKEM_GET_OLD_EK_PUB_LEN_F_ID 9
#define MLKEM_GET_OLD_PRIV_LEN_F_ID   10
#define MLKEM_TRIGGER_FAIL_F_ID       11

typedef MSTATUS (mlkem_key_validity_check_f)(ubyte *pIn, ubyte4 inLen);
typedef MSTATUS (mlkem_key_hash_check_f)(MLKEMCtx *ctx, const MlkemCtx *pCtx);
typedef MSTATUS (mlkem_keygen_internal_f)(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pD,
				    ubyte *pZ, ubyte *pDk);
typedef MSTATUS (mlkem_encaps_internal_f)(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pEk,
				    ubyte *pM, ubyte *pC, ubyte *pK);
typedef MSTATUS (mlkem_decaps_internal_f)(MOC_HASH(hwAccelDescr hwAccelCtx) const MlkemCtx *pCtx, ubyte *pDk,
				    ubyte *pC, ubyte *pK);
typedef const MlkemCtx* (mlkem_get_old_ctx_f)(MLKEMType type);
typedef ubyte4 (mlkem_get_old_cipher_len_f)(const MlkemCtx* ctx);
typedef ubyte4 (mlkem_get_old_dk_pub_len_f)(const MlkemCtx* ctx);
typedef ubyte4 (mlkem_get_old_ek_pub_len_f)(const MlkemCtx* ctx);
typedef ubyte4 (mlkem_get_old_priv_len_f)(const MlkemCtx* ctx);

MOC_EXTERN const FIPS_entry_fct* MLKEM_getPrivileged();

#ifdef __cplusplus
}
#endif

#endif /* __MLKEM_PRIV_HEADER__ */
