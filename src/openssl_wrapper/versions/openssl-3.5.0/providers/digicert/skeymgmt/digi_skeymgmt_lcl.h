/*
 * digi_skeymgmt_lcl.h
 *
 * Symmetric Key Management header for OSSL 3.5 provider ADAPTED FROM OPENSSL CODE
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
/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef DIGI_SKEYMGMT_LCL_H
# define DIGI_SKEYMGMT_LCL_H
# pragma once
# include <openssl/core_dispatch.h>

OSSL_FUNC_skeymgmt_import_fn digi_generic_import;
OSSL_FUNC_skeymgmt_export_fn digi_generic_export;
OSSL_FUNC_skeymgmt_free_fn digi_generic_free;

#endif
