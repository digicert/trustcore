/*
 * moc_stream.h
 *
 * Mocana Simple Stream Factory Header
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

MOC_EXTERN MSTATUS MOC_STREAM_open (streamDescr **ppRetStreamDescr, void* outStream, ubyte4 buflen, funcStreamWriteData pFuncWriteData);
MOC_EXTERN MSTATUS MOC_STREAM_write(streamDescr *pStreamDescr, ubyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pRetNumBytesWritten);
MOC_EXTERN MSTATUS MOC_STREAM_flush(streamDescr *pStreamDescr, ubyte4 *pRetNumBytesPending, intBoolean *pFlushComplete);
MOC_EXTERN MSTATUS MOC_STREAM_close(streamDescr **ppFreeStreamDescr);

#ifdef __cplusplus
}
#endif

#endif /* __MOC_STREAM_HEADER__ */
