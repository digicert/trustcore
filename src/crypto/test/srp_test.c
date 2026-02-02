/*
 * srp_test.c
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/memory_debug.h"

#include "../../crypto/sha1.h"
#include "../../crypto/dh.h"
#include "../../crypto/srp.h"

#include "../../../unit_tests/unittest.h"


int srp_test_rfc5054()
{
    int retVal = 0;

#if defined(__DIGICERT_MIN_SRP_BITS__) && __DIGICERT_MIN_SRP_BITS__ <= 1024 
    sbyte4 resCmp;
    ubyte* verifier = 0;
    ubyte4 verifierLen;
    ubyte* I = (ubyte*) "alice";
    ubyte* P = (ubyte*) "password123";
    hwAccelDescr hwAccelCtx;

    ubyte salt[] =
    {
        0xBE, 0xB2, 0x53, 0x79, 0xD1, 0xA8, 0x58, 0x1E,
        0xB5, 0xA7, 0x27, 0x67, 0x3A, 0x24, 0x41, 0xEE
    };
    const ubyte expectedVerifier[] =
    {
        0x7e, 0x27, 0x3d, 0xe8, 0x69, 0x6f, 0xfc, 0x4f, 0x4e, 0x33, 0x7d, 0x05,
        0xb4, 0xb3, 0x75, 0xbe, 0xb0, 0xdd, 0xe1, 0x56, 0x9e, 0x8f, 0xa0, 0x0a,
        0x98, 0x86, 0xd8, 0x12, 0x9b, 0xad, 0xa1, 0xf1, 0x82, 0x22, 0x23, 0xca,
        0x1a, 0x60, 0x5b, 0x53, 0x0e, 0x37, 0x9b, 0xa4, 0x72, 0x9f, 0xdc, 0x59,
        0xf1, 0x05, 0xb4, 0x78, 0x7e, 0x51, 0x86, 0xf5, 0xc6, 0x71, 0x08, 0x5a,
        0x14, 0x47, 0xb5, 0x2a, 0x48, 0xcf, 0x19, 0x70, 0xb4, 0xfb, 0x6f, 0x84,
        0x00, 0xbb, 0xf4, 0xce, 0xbf, 0xbb, 0x16, 0x81, 0x52, 0xe0, 0x8a, 0xb5,
        0xea, 0x53, 0xd1, 0x5c, 0x1a, 0xff, 0x87, 0xb2, 0xb9, 0xda, 0x6e, 0x04,
        0xe0, 0x58, 0xad, 0x51, 0xcc, 0x72, 0xbf, 0xc9, 0x03, 0x3b, 0x56, 0x4e,
        0x26, 0x48, 0x0d, 0x78, 0xe9, 0x55, 0xa5, 0xe2, 0x9e, 0x7a, 0xb2, 0x45,
        0xdb, 0x2b, 0xe3, 0x15, 0xe2, 0x09, 0x9a, 0xfb
    };

    UNITTEST_STATUS_GOTO(0, HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx),
                         retVal, exit);

    UNITTEST_STATUS_GOTO(0, SRP_computeVerifier(MOC_HASH(hwAccelCtx)
                                                salt, sizeof(salt),
                                                I, DIGI_STRLEN((sbyte*)I),
                                                P, DIGI_STRLEN((sbyte*)P),
                                                1024,
                                                &verifier, &verifierLen),
                         retVal, exit);

    retVal += UNITTEST_TRUE(0, verifier != 0);
    retVal += UNITTEST_INT(0, verifierLen, sizeof(expectedVerifier));

    if (retVal) goto exit;

    DIGI_MEMCMP(expectedVerifier, verifier, verifierLen, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

exit:

    FREE(verifier);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);
#endif
    
    return retVal;

}
