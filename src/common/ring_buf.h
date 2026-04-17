/*
 * ring_buf.h
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
