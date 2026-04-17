/*
 *  hardware_accel_crypto.h
 *  ssl
 *
 * SSL Developer API
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

#ifndef __HARDWARE_ACCEL_SUPPORT_HEADER__
#define __HARDWARE_ACCEL_SUPPORT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_HARDWARE_ACCEL_CRYPTO__

void FREE_ALIGN( void* ptr, int cryptoType);
void* MALLOC_ALIGN(int size, int cryptoType);

MSTATUS MD5CopyCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) MD5_CTXHS* dest, const MD5_CTXHS* src);
void MD5FreeCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) MD5_CTXHS* p);
MSTATUS SHA1_CopyCtxHandShake(MOC_HASH(hwAccelDescr hwAccelCookie) shaDescrHS* dest, const shaDescrHS* src);
void SHA1_FreeCtxHandShake(MOC_HASH(hwAccelDescr hwAccelCookie) shaDescrHS* p);

MSTATUS CopyCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) void* dest, const void* src, ubyte4 objectSize);
void FreeCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) void* p, ubyte4 objectSize);

#endif


#ifdef __cplusplus
}
#endif

#endif /* __HARDWARE_ACCEL_SUPPORT_HEADER__ */
