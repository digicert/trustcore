/*
 * sshc_client.h
 *
 * SSH Developer API
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

#ifndef __SSHC_CLIENT_HEADER__
#define __SSHC_CLIENT_HEADER__

typedef struct
{
    sbyte4              instance;
    sshClientContext*   pContextSSH;
    sbyte4              connectionState;

    sbyte4              isSocketClosed;
    ubyte4              serverPort;
    TCP_SOCKET          socket;

    /* non-blocking read data buffers */
    ubyte*              pReadBuffer;
    ubyte*              pReadBufferPosition;
    ubyte4              numBytesRead;

    /* synchronous simulation upcall handler data */
    circBufDescr*       pCircBufDescr;

    /* synchronous simulation upcall handler data */
    sbyte4              mesgType;
    ubyte*              pRetBuffer;
    ubyte4*             pRetBufferSize;

    ubyte*              pBuffer;
    ubyte4              numBytesInBuffer;

    ubyte4              offsetInBuffer;
    void*               cookie;

} sshcConnectDescr;

#endif /* __SSHC_CLIENT_HEADER__ */
