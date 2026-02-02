/*
 * stack_test.c
 *
 * unit test for stack.c
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
