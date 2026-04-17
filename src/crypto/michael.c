/*
 * michael.c
 *
 * 802.11i: Michael Message Integrity Check Algorithm
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_WIFI__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../crypto/michael.h"


/*------------------------------------------------------------------*/

#define XSWAP(X)                (((((ubyte4)(X)) >> 8) & 0x00ff00ff) | ((((ubyte4)(X)) << 8) & 0xff00ff00))


/*------------------------------------------------------------------*/

static void
MICHAEL_blockFunction(ubyte4* pL, ubyte4* pR)
{
    ubyte4 L, R;

    L = *pL;
    R = *pR;

    R = R ^ ROTATE_LEFT(L,17);
    L = L + R;
    R = R ^ XSWAP(L);
    L = L + R;
    R = R ^ ROTATE_LEFT(L,3);
    L = L + R;
    R = R ^ ROTATE_RIGHT(L,2);
    L = L + R;

    *pL = L;
    *pR = R;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MICHAEL_generateMic(ubyte *K, ubyte *M, ubyte4 mdsuLen, ubyte *pMIC)
{
    ubyte4  L, R;
    sbyte4  offset;
    sbyte4  numBlocks;

    numBlocks = mdsuLen / 4;
    offset = 0;

    L = (ubyte4)K[0] + ((ubyte4)K[1] << 8) + ((ubyte4)K[2] << 16) + ((ubyte4)K[3] << 24);
    R = (ubyte4)K[4] + ((ubyte4)K[5] << 8) + ((ubyte4)K[6] << 16) + ((ubyte4)K[7] << 24);

    while (numBlocks)
    {
        L = L ^ ((ubyte4)M[offset] | ((ubyte4)M[offset + 1] << 8) | ((ubyte4)M[offset + 2] << 16) | ((ubyte4)M[offset + 3] << 24));
        MICHAEL_blockFunction(&L, &R);

        offset = offset + 4;
        numBlocks--;
    }

    pMIC[0] = (ubyte)(L & 0xff);
    pMIC[1] = (ubyte)((L >> 8) & 0xff);
    pMIC[2] = (ubyte)((L >> 16) & 0xff);
    pMIC[3] = (ubyte)((L >> 24) & 0xff);

    pMIC[4] = (ubyte)(R & 0xff);
    pMIC[5] = (ubyte)((R >> 8) & 0xff);
    pMIC[6] = (ubyte)((R >> 16) & 0xff);
    pMIC[7] = (ubyte)((R >> 24) & 0xff);

    return OK;

} /* MICHAEL_generateMic */

#endif /* __ENABLE_DIGICERT_WIFI__ */

