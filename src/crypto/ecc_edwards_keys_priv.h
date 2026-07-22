/*
 * ecc_edwards_keys_priv.h
 *
 * EDDSA Internal Functions for NIST Testing
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

#ifndef __ECC_EDWARDS_KEYS_PRIV_HEADER__
#define __ECC_EDWARDS_KEYS_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define EDDSA_TRIGGER_FAIL_F_ID   1

MOC_EXTERN const FIPS_entry_fct* EDDSA_getPrivileged(void);

#ifdef __cplusplus
}
#endif
#endif /* __ECC_EDWARDS_KEYS_PRIV_HEADER__ */
