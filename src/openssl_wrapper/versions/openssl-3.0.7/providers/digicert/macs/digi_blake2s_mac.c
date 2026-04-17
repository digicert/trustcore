/*
 * digi_blake2s_mac.c
 *
 * Blake2s implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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
 * Copyright 2018-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Constants */
#define BLAKE2_KEYBYTES MOC_BLAKE2S_MAX_KEYLEN
#define BLAKE2_OUTBYTES MOC_BLAKE2S_MAX_OUTLEN
#define BLAKE2_BLOCKBYTES MOC_BLAKE2S_BLOCKLEN

/* OSSL_DISPATCH symbol */
#define BLAKE2_FUNCTIONS digiprov_blake2smac_functions

/* Digicert methods */
#define CRYPTO_INTERFACE_BLAKE_alloc CRYPTO_INTERFACE_BLAKE_2S_alloc
#define CRYPTO_INTERFACE_BLAKE_init CRYPTO_INTERFACE_BLAKE_2S_init
#define CRYPTO_INTERFACE_BLAKE_update CRYPTO_INTERFACE_BLAKE_2S_update
#define CRYPTO_INTERFACE_BLAKE_final CRYPTO_INTERFACE_BLAKE_2S_final
#define CRYPTO_INTERFACE_BLAKE_delete CRYPTO_INTERFACE_BLAKE_2S_delete
#define CRYPTO_INTERFACE_BLAKE_cloneCtx CRYPTO_INTERFACE_BLAKE_2S_cloneCtx

#define BLAKE2_CTX BLAKE2S_CTX

#include "digi_blake2_mac.c"
