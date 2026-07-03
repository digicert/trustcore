/*
 * digi_aes_skmgmt.c
 *
 * AES key management implementations for OSSL 3.5 provider ADAPTED FROM OPENSSL CODE
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

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#ifdef CONTEXT
#undef CONTEXT
#endif

#ifdef BOOLEAN
#undef BOOLEAN
#endif

#include "digiprov.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "crypto/types.h"
#include "internal/skey.h"
#include "prov/provider_ctx.h"
#include "digi_skeymgmt_lcl.h"

static OSSL_FUNC_skeymgmt_import_fn digi_aes_import;
static OSSL_FUNC_skeymgmt_export_fn digi_aes_export;

static void *digi_aes_import(void *provctx, int selection, const OSSL_PARAM params[])
{
    PROV_SKEY *aes = digi_generic_import(provctx, selection, params);

    if (aes == NULL)
        return NULL;

    if (aes->length != 16 && aes->length != 24 && aes->length != 32 && aes->length != 64) /* aes-xts-256 is two 32 byte keys */ 
    {
        digi_generic_free(aes);
        return NULL;
    }
    aes->type = SKEY_TYPE_AES;

    return aes;
}

static int digi_aes_export(void *keydata, int selection, OSSL_CALLBACK *param_callback, void *cbarg)
{
    PROV_SKEY *aes = keydata;

    if (aes->type != SKEY_TYPE_AES)
        return 0;

    return digi_generic_export(keydata, selection, param_callback, cbarg);
}

const OSSL_DISPATCH digiprov_aes_skeymgmt_functions[] = 
{
    { OSSL_FUNC_SKEYMGMT_FREE, (void (*)(void))digi_generic_free },
    { OSSL_FUNC_SKEYMGMT_IMPORT, (void (*)(void))digi_aes_import },
    { OSSL_FUNC_SKEYMGMT_EXPORT, (void (*)(void))digi_aes_export },
    OSSL_DISPATCH_END
};
