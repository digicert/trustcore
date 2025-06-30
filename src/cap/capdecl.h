/*
 * capdecl.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
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
