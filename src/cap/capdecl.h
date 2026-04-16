/*
 * capdecl.h
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
 * This file will contain any forward declarations that may
 * be neccessary for NanoCAP.
 */

/**
@file       capdecl.h
@brief      brief
@details    Add details here.

@filedoc    capdecl.h
*/
#ifndef CAP_DECL_H
#define CAP_DECL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations for the MocSymCtx struct.
 *
 * The existing NanoCrypto structs will have a MocSymCtx
 * pointer added to them. The NanoCAP layer will use this
 * MocSymCtx to perform symmetric operations.
 */
struct MocSymContext;
typedef struct MocSymContext *MocSymCtx;

/* Forward declarations for the MocAsymKey struct.
 *
 * The existing NanoCrypto structs will have a MocAsymKey
 * pointer added to them. The NanoCAP layer will use this
 * MocAsymKey to perform asymmetric operations.
 */
struct MocAsymmetricKey;
typedef struct MocAsymmetricKey *MocAsymKey;


/* Forward declarations for the MocCtx struct.
 *
 * This is a library wide context for NanoCAP that contains
 * a list of operators that can perform cryptographic operations.
 */
struct MocContext;
struct MocSubCtx;
typedef struct MocContext *MocCtx;

#ifdef __cplusplus
}
#endif

#endif /* CAP_DECL_H */
