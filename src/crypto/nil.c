/*
 * nil.c
 *
 * NIL Encipher & Decipher
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/nil.h"


/*------------------------------------------------------------------*/

#ifdef __ENABLE_NIL_CIPHER__

extern BulkCtx
CreateNilCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    static sbyte4 dummy = 0;
    MOC_UNUSED(keyMaterial);
    MOC_UNUSED(keyLength);
    MOC_UNUSED(encrypt);

    return (BulkCtx)(&dummy);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteNilCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;

    *ctx = NULL;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DoNil(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MOC_UNUSED(ctx);
    MOC_UNUSED(data);
    MOC_UNUSED(dataLength);
    MOC_UNUSED(encrypt);
    MOC_UNUSED(iv);

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CloneNil(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MOC_UNUSED(pCtx);
    MOC_UNUSED(ppNewCtx);

    return OK;
}
#endif /* __ENABLE_NIL_CIPHER__ */
