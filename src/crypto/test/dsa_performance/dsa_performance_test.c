/*
 * dsa_performance_test.c
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

#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/mdefs.h"
#include "../../../common/merrors.h"

#include "../../../../unit_tests/unittest.h"
#include "../performance_test.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
dsa_performance_test()
{
	int status = 0;
	int retVal = 0;
	int hint = 0;

	retVal += UNITTEST_STATUS(hint, status = (MSTATUS) DIGICERT_initDigicert());
	if (OK > status)  goto exit;

	performance_test_all();

exit:
	DIGICERT_freeDigicert();
	return UNITTEST_STATUS(hint, status);
}




