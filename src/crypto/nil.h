/*
 * nil.h
 *
 * NIL Header
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


/*------------------------------------------------------------------*/

#ifndef __NIL_HEADER__
#define __NIL_HEADER__

#ifdef __ENABLE_NIL_CIPHER__

MOC_EXTERN BulkCtx CreateNilCtx (MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
MOC_EXTERN MSTATUS DeleteNilCtx (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx);
MOC_EXTERN MSTATUS DoNil        (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
MOC_EXTERN MSTATUS CloneNil     (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#endif /* __ENABLE_NIL_CIPHER__ */

#endif /* __NIL_HEADER__ */
