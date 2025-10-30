/*
*  hardware_accel_support.h
*  ssl
*
* SSL Developer API
*
* Copyright Mocana Corp 2003-2007. All Rights Reserved.
* Proprietary and Confidential Material.
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
