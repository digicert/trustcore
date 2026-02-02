/*
 * md45.c
 *
 * Shared MD4/MD5 implementation
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
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
