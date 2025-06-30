/*
 * nil.h
 *
 * NIL Header
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
