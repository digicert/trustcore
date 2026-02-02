/*
 * ring_buf.h
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

typedef struct
    {
        ubyte*      pBuffer;    /* streamed data */
        ubyte4      buflen;     /* size of the ring buffer */
        ubyte4      head;       /* ring head */
        ubyte4      tail;       /* ring tail */
        ubyte       empty;
        ubyte       full;
        
    } ringBufDescr;

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS RING_BUF_create    (ringBufDescr **ppRetCircBufDescr, ubyte4 buflen);
MOC_EXTERN MSTATUS RING_BUF_release   (ringBufDescr **ppFreeCircBufDescr);

MOC_EXTERN MSTATUS RING_BUF_write     (ringBufDescr *pCircBufDescr, ubyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pRetNumBytesWritten);
MOC_EXTERN MSTATUS RING_BUF_read      (ringBufDescr *pCircBufDescr, ubyte *pReadBuffer, ubyte4 numBytesToRead, ubyte4 *pRetNumBytesRead);
MOC_EXTERN MSTATUS RING_BUF_peek      (ringBufDescr *pCircBufDescr, ubyte *pReadBuffer, ubyte4 numBytesToRead, ubyte4 *pRetNumBytesRead);
MOC_EXTERN MSTATUS RING_BUF_read_byte(ringBufDescr *pRingBufDescr, ubyte * pReadByte);
MOC_EXTERN MSTATUS RING_BUF_write_byte(ringBufDescr *pRingBufDescr, ubyte * pWriteByte);
MOC_EXTERN intBoolean RING_BUF_isEmpty(ringBufDescr *pRingBufDescr);
