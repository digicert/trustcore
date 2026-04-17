/*
 * stack_test.c
 *
 * unit test for stack.c
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

#include "../../common/moptions.h"

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/stack.h"

#include "../../../unit_tests/unittest.h"

int stack_test_all()
{
	int retVal = 0;
	ubyte4 data1 = 5;
	sbyte* data2 = "This is a test";
	void* data3;

	stack *S = MALLOC(sizeof(stack));

    retVal += UNITTEST_TRUE(0, 0 != S);

	stack_init(S, sizeof(void*), 1);
	retVal += UNITTEST_TRUE(0, stack_isEmpty(S));
    if (retVal) goto exit;

    stack_push(S, (void*)data1);
	stack_push(S, (void*)data2);

	stack_pop(S, &data3);

	retVal += UNITTEST_TRUE(0, 0 == DIGI_STRCMP(data2, data3));
	if (retVal)	goto exit;

	stack_pop(S, &data3);

	retVal += UNITTEST_TRUE(0, (0 == (data1 - (ubyte4)data3)));
	if (retVal)	goto exit;

	retVal += UNITTEST_TRUE(0, stack_isEmpty(S));
    if (retVal) goto exit;

exit:
    if (S)
    {
        stack_uninit(S, NULL);
        FREE(S);
    }

	return retVal;
}

//int main(int argc, char* argv[])
//{
//    return stack_test_all();
//}
