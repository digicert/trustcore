/*
 * fips_test.c
 *
 * FIPS 140 Compliance
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
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"

#include "../../../unit_tests/unittest.h"

#include "../fips.h"

int fips_test_all()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    /* Main FIPS Tests */
    retVal += UNITTEST_STATUS(0, FIPS_powerupSelfTest());

    /* Sub FIPS Tests */
    retVal += UNITTEST_STATUS(0, FIPS_knownAnswerTests());

    /* Algorithm Specific FIPS Tests */
    retVal += UNITTEST_STATUS(0, FIPS_randomKat());

    retVal += UNITTEST_STATUS(0, FIPS_sha1Kat());

    retVal += UNITTEST_STATUS(0, FIPS_sha256Kat());

    retVal += UNITTEST_STATUS(0, FIPS_sha512Kat());

    retVal += UNITTEST_STATUS(0, FIPS_hmacKat());

    retVal += UNITTEST_STATUS(0, FIPS_tripleDesKat());

    retVal += UNITTEST_STATUS(0, FIPS_aesKat());

    retVal += UNITTEST_STATUS(0, FIPS_dsaKat());

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    return retVal;
}
