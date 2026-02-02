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




