/*
 * mbitmap.h
 *
 * Mocana Bit Map Factory Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
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
