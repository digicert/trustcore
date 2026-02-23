/*
 * digi_blake2s_mac.c
 *
 * Blake2s implementations for OSSL 3.0 provider ADAPTED FROM openssl code
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
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
