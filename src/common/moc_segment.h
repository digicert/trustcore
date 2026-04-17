/*
 * moc_segment.h
 *
 * Segmented Buffer
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

#ifndef __MOC_SEGMENT_HEADER__
#define __MOC_SEGMENT_HEADER__

#define GET_SEG_BUFFER(X)       ((X)->pBuff)
#define GET_SEG_BUFFER_LEN(X)   ((X)->buffLen)
#define GET_SEG_BYTES_USED(X)   ((X)->numBytesUsed)
#define GET_NEXT_SEG(X)         ((X)->pNextSeg)


/*------------------------------------------------------------------*/

typedef struct mocSegDescr
{
    ubyte*              pBuff;
    ubyte4              buffLen;
    ubyte4              numBytesUsed;

    ubyte*              pFreeArg;

    struct mocSegDescr* pNextSeg;

}mocSegDescr;


/*------------------------------------------------------------------*/

MOC_EXTERN sbyte4 DIGI_copyToSeg(const ubyte* pSrcBuf, ubyte4 srcBufLen, mocSegDescr *pDestBufSeg, ubyte4 offset);
MOC_EXTERN sbyte4 DIGI_copyToSegEx(const ubyte* pSrcBuf, ubyte4 srcBufLen, mocSegDescr *pDestBufSeg, ubyte4 offset,
                              mocSegDescr** ppNewBufSeg, ubyte4* pNewOff);
MOC_EXTERN sbyte4 DIGI_copyFromSeg(const mocSegDescr *pSrcBufSeg, ubyte4 offset, ubyte* pDestBuf, ubyte4 destBufLen);
MOC_EXTERN sbyte4 DIGI_copyFromSegEx(const mocSegDescr *pSrcBufSeg, ubyte4 offset, ubyte* pDestBuf, ubyte4 destBufLen,
                                mocSegDescr** ppNewBufSeg, ubyte4* pNewOff);

MOC_EXTERN MSTATUS DIGI_memsetSeg(mocSegDescr *pSrcBufSeg, ubyte valueToSet, ubyte4 numBytesToSet, ubyte4 offset);
MOC_EXTERN MSTATUS DIGI_setByteInSeg(ubyte value, mocSegDescr *pDestBufSeg, ubyte4 offset);


MOC_EXTERN ubyte4 SEG_findSegment(const mocSegDescr **ppSrcBufSeg, ubyte4 offset);

/* for testing */
MOC_EXTERN MSTATUS DIGI_createTestSeg(mocSegDescr **ppBufSeg, ubyte4 numSeg, ubyte4 segBufSize);
MOC_EXTERN MSTATUS DIGI_freeTestSeg(mocSegDescr **ppBufSeg);
MOC_EXTERN MSTATUS DIGI_clearTestSeg(mocSegDescr *pBufSeg);

#endif /* __MOC_SEGMENT_HEADER__ */
