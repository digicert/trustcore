/*
 * circ_buf.h
 *
 * Circular Buffer Factory Header
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


/*------------------------------------------------------------------*/

#ifndef __CIRC_BUF_HEADER__
#define __CIRC_BUF_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

typedef struct
{
    ubyte*      pBuffer;    /* streamed data */
    ubyte4      buflen;     /* size of the circ buffer */
    ubyte4      head;       /* circ head */
    ubyte4      tail;       /* circ tail */

} circBufDescr;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CIRC_BUF_create    (circBufDescr **ppRetCircBufDescr, ubyte4 buflen);
MOC_EXTERN MSTATUS CIRC_BUF_release   (circBufDescr **ppFreeCircBufDescr);

MOC_EXTERN MSTATUS CIRC_BUF_write     (circBufDescr *pCircBufDescr, ubyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pRetNumBytesWritten);
MOC_EXTERN MSTATUS CIRC_BUF_read      (circBufDescr *pCircBufDescr, ubyte *pReadBuffer, ubyte4 numBytesToRead, ubyte4 *pRetNumBytesRead);
MOC_EXTERN MSTATUS CIRC_BUF_bytesAvail(circBufDescr *pCircBufDescr, ubyte4 *pRetNumBytesPending);

#ifdef __cplusplus
}
#endif

#endif /* __CIRC_BUF_HEADER__ */
