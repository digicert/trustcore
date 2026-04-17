/*
 * mtcp.c
 *
 * Mocana TCP Abstraction Layer
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

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"


/*------------------------------------------------------------------*/

extern MSTATUS
TCP_READ_ALL(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 bytesToRead,
             ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
    ubyte4  bytesRead;
    ubyte4  totalBytesRead;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesRead))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumBytesRead = totalBytesRead = 0;

    do
    {
        status = TCP_READ_AVL(socket, pBuffer + totalBytesRead,
                              bytesToRead - totalBytesRead, &bytesRead, msTimeout);

        if (OK > status)
            break;

        totalBytesRead += bytesRead;

    } while (totalBytesRead < bytesToRead);

    *pNumBytesRead = totalBytesRead;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
TCP_WRITE_ALL(TCP_SOCKET socket, sbyte *pBuffer, ubyte4 numBytesToWrite,
                      ubyte4 *pNumBytesWritten)
{
    ubyte4 bytesWritten;
    ubyte4 totalBytesWritten;
    MSTATUS status;

    if ((NULL == pBuffer) || (NULL == pNumBytesWritten))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumBytesWritten = totalBytesWritten = 0;

    do
    {
        status = TCP_WRITE(socket, pBuffer + totalBytesWritten,
                           numBytesToWrite - totalBytesWritten, &bytesWritten);

        if (OK > status)
            break;

        totalBytesWritten += bytesWritten;

    } while (totalBytesWritten < numBytesToWrite);

    *pNumBytesWritten = totalBytesWritten;

exit:
    return status;
}


/*------------------------------------------------------------------*/
