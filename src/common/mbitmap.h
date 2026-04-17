/*
 * mbitmap.h
 *
 * Digicert Bit Map Factory Header
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
 */

#ifndef __MBITMAP_HEADER__
#define __MBITMAP_HEADER__

typedef struct
{
    ubyte4* pBitmap;
    ubyte4  bitmapSize;
    ubyte4  bitmapLoIndex;
    ubyte4  bitmapHiIndex;

} bitmapDescr;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MBITMAP_findVacantIndex(bitmapDescr *pBitMapDescr, ubyte4 *pRetIndex);
MOC_EXTERN MSTATUS MBITMAP_testAndSetIndex(bitmapDescr *pBitMapDescr, ubyte4 theIndex);
MOC_EXTERN MSTATUS MBITMAP_clearIndex(bitmapDescr *pBitMapDescr, ubyte4 theIndex);
MOC_EXTERN MSTATUS MBITMAP_isIndexSet(bitmapDescr *pBitMapDescr, ubyte4 theIndex, intBoolean *pIsIndexSet);
MOC_EXTERN MSTATUS MBITMAP_createMap(bitmapDescr **ppRetBitMapDescr, ubyte4 loIndex, ubyte4 hiIndex);
MOC_EXTERN MSTATUS MBITMAP_releaseMap(bitmapDescr **ppFreeBitMapDescr);

#endif /* __MBITMAP_HEADER__ */
