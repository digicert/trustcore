/*
 * sshc_client.h
 *
 * SSH Developer API
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
