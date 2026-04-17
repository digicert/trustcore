/*
 * moc_stream.h
 *
 * DigiCert Simple Stream Factory Header
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


/*------------------------------------------------------------------*/

#ifndef __MOC_STREAM_HEADER__
#define __MOC_STREAM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

typedef MSTATUS(*funcStreamWriteData)(void* outStream, ubyte *pBufferToSend, ubyte4 numBytesToWrite, ubyte4 *pNumBytesWritten);

typedef struct
{
    void*      outStream;  /* socket id, connection instance, etc */

    ubyte*      pBuffer;    /* streamed data */
    ubyte4      buflen;     /* size of the circ buffer */
    ubyte4      head;       /* circ head */
    ubyte4      tail;       /* circ tail */

    /* method for sending out buffer data */
    funcStreamWriteData pFuncWriteData;

} streamDescr;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS DIGI_STREAM_open (streamDescr **ppRetStreamDescr, void* outStream, ubyte4 buflen, funcStreamWriteData pFuncWriteData);
MOC_EXTERN MSTATUS DIGI_STREAM_write(streamDescr *pStreamDescr, ubyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pRetNumBytesWritten);
MOC_EXTERN MSTATUS DIGI_STREAM_flush(streamDescr *pStreamDescr, ubyte4 *pRetNumBytesPending, intBoolean *pFlushComplete);
MOC_EXTERN MSTATUS DIGI_STREAM_close(streamDescr **ppFreeStreamDescr);

#ifdef __cplusplus
}
#endif

#endif /* __MOC_STREAM_HEADER__ */
