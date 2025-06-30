/*
 * moc_segment.h
 *
 * Segmented Buffer
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

MOC_EXTERN sbyte4 MOC_copyToSeg(const ubyte* pSrcBuf, ubyte4 srcBufLen, mocSegDescr *pDestBufSeg, ubyte4 offset);
MOC_EXTERN sbyte4 MOC_copyToSegEx(const ubyte* pSrcBuf, ubyte4 srcBufLen, mocSegDescr *pDestBufSeg, ubyte4 offset,
                              mocSegDescr** ppNewBufSeg, ubyte4* pNewOff);
MOC_EXTERN sbyte4 MOC_copyFromSeg(const mocSegDescr *pSrcBufSeg, ubyte4 offset, ubyte* pDestBuf, ubyte4 destBufLen);
MOC_EXTERN sbyte4 MOC_copyFromSegEx(const mocSegDescr *pSrcBufSeg, ubyte4 offset, ubyte* pDestBuf, ubyte4 destBufLen,
                                mocSegDescr** ppNewBufSeg, ubyte4* pNewOff);

MOC_EXTERN MSTATUS MOC_memsetSeg(mocSegDescr *pSrcBufSeg, ubyte valueToSet, ubyte4 numBytesToSet, ubyte4 offset);
MOC_EXTERN MSTATUS MOC_setByteInSeg(ubyte value, mocSegDescr *pDestBufSeg, ubyte4 offset);


MOC_EXTERN ubyte4 SEG_findSegment(const mocSegDescr **ppSrcBufSeg, ubyte4 offset);

/* for testing */
MOC_EXTERN MSTATUS MOC_createTestSeg(mocSegDescr **ppBufSeg, ubyte4 numSeg, ubyte4 segBufSize);
MOC_EXTERN MSTATUS MOC_freeTestSeg(mocSegDescr **ppBufSeg);
MOC_EXTERN MSTATUS MOC_clearTestSeg(mocSegDescr *pBufSeg);

#endif /* __MOC_SEGMENT_HEADER__ */
