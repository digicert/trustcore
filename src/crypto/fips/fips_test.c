/*
 * fips_test.c
 *
 * FIPS 140 Compliance
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
