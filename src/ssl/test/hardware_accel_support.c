/*
 * hardware_accel_support.c
 *
 * Support for the __ENABLE_HARDWARE_ACCEL_CRYPTO__ enable SSL code
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
