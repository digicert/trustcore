/*
 * hardware_accel_support.c
 *
 * Support for the __ENABLE_HARDWARE_ACCEL_CRYPTO__ enable SSL code
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
 */


#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"

#include "../../ssl/hardware_accel_crypto.h"

#ifdef __ENABLE_HARDWARE_ACCEL_CRYPTO__

void FREE_ALIGN( void* ptr, int cryptoType)
{
    FREE(ptr);
}

void* MALLOC_ALIGN(int size, int cryptoType)
{
    if (0 == size)
        return NULL;

    return MALLOC(size);
}


MSTATUS MD5CopyCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) MD5_CTXHS* dest, const MD5_CTXHS* src)
{
    return DIGI_MEMCPY( dest, src, sizeof(MD5_CTXHS));
}

void MD5FreeCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) MD5_CTXHS* p)
{
    /* no op */
}

MSTATUS SHA1_CopyCtxHandShake(MOC_HASH(hwAccelDescr hwAccelCookie) shaDescrHS* dest, const shaDescrHS* src)
{
    return DIGI_MEMCPY( dest, src, sizeof(shaDescrHS));
}

void SHA1_FreeCtxHandShake(MOC_HASH(hwAccelDescr hwAccelCookie) shaDescrHS* p)
{
    /* no op */
}

/* new for TLS 1.2 support */
MSTATUS CopyCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) void* dest, const void* src, ubyte4 objectSize)
{
    return DIGI_MEMCPY(dest, src, objectSize);
}

void FreeCtx_HandShake(MOC_HASH(hwAccelDescr hwAccelCookie) void* p, ubyte4 objectSize)
{
    /* no op */
}



#endif
