/*
 * md45.c
 *
 * Shared MD4/MD5 implementation
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

#if (defined(__ENABLE_DIGICERT_MD4__) && !defined(__MD4_HARDWARE_HASH__)) || !defined(__MD5_HARDWARE_HASH__)

#include "../common/mtypes.h"

#include "../crypto/md45.h"

const ubyte MD45_PADDING[64] =
{
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Encodes input (ubyte4) into output (ubyte). Assumes len is a multiple of 4. */
extern void
MD45_encode(ubyte *output, const ubyte4 *input, ubyte4 len)
{
    ubyte4 i, j;

    for (i = 0, j = 0; j < len; i++, j += 4)
    {
        output[j]   = (ubyte)(input[i] & 0xff);
        output[j+1] = (ubyte)((input[i] >> 8) & 0xff);
        output[j+2] = (ubyte)((input[i] >> 16) & 0xff);
        output[j+3] = (ubyte)((input[i] >> 24) & 0xff);
    }
}

/* Decodes input (ubyte) into output (ubyte4). Assumes len is a multiple of 4. */
extern void
MD45_decode(ubyte4 *output, const ubyte *input, ubyte4 len)
{
    ubyte4 i, j;

    for (i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((ubyte4)input[j]) | (((ubyte4)input[j+1]) << 8) |
                    (((ubyte4)input[j+2]) << 16) | (((ubyte4)input[j+3]) << 24);
}

#endif /* (defined(__ENABLE_DIGICERT_MD4__) && !defined(__MD4_HARDWARE_HASH__)) || !defined(__MD5_HARDWARE_HASH__) */
