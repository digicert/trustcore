/*
 * timer_test.c
 *
 * unit test for timer.c
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

#include "../timer.c"

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_OSX__)
#include <stdio.h>
#endif

/*---------------------------------------------------------------------------*/

/* FIXME: use the unittest.h macros instead of this */
#define TEST_IT(X)      if (X) { error_line = __LINE__; status = (OK > status) ?  status : -1; goto exit; } numTests++


/*---------------------------------------------------------------------------*/

static int error_line;


/*--------------------------------------------------------------------------*/
ubyte * gTimer1;
ubyte * gTimer2;
ubyte gCb1;
ubyte gCb2;

int  testResult = 0;
int  numTests = 0;

#define TIMER1_TIMEOUT 5
#define TIMER2_TIMEOUT 10 
ubyte4  currentTimeMSInit ;

static void
utils_TimeoutCallback2(void *session, ubyte *type)
{

    ubyte4 currentTimeMS = RTOS_getUpTimeInMS();
    /* FIXME: stdio.h required */
    printf("CB2 session %p gCb1 %p gCB2 %p\n", session,&gCb1,&gCb2); 
    printf("Current TimeOut %d\n", (sbyte4)currentTimeMS);
    printf("gCB2 Shoudl Expired after %d MSSec\n", TIMER2_TIMEOUT * 1000); 
    printf("gCB2 Expired after %d MSSec\n", currentTimeMS - currentTimeMSInit); 
    return;
}

static void
utils_TimeoutCallback(void *session, ubyte *type)
{

    ubyte4 currentTimeMS = RTOS_getUpTimeInMS();
    printf("CB1 session %p gCb1 %p gCB2 %p\n", session,&gCb1,&gCb2); 
    printf("Current TimeOut %d\n", (sbyte4)currentTimeMS);
    printf("gCB1 Shoudl Expired after %d MSSec\n", TIMER1_TIMEOUT * 1000); 
    printf("gCB1 Expired after %d MSSec\n", currentTimeMS - currentTimeMSInit); 

    return;
}

int timer_test_all()
{
	int retVal =0;
    MSTATUS status;
	sbyte4 i;

    
    /* Initialize Timer Queue */
    /* Cannot Create Timer without initing it */ 
    TEST_IT(OK <= (status = TIMER_createTimer(utils_TimeoutCallback,&gTimer1)));

    TEST_IT(OK > (status = TIMER_initTimer()));

    /* Test Null Ptr */ 
    TEST_IT(OK <= (status = TIMER_createTimer(NULL,NULL)));
    /* This Should work */
    TEST_IT(OK > (status = TIMER_createTimer(utils_TimeoutCallback,&gTimer1)));

     /* This Shoudl Fail  As the timer has not been created*/ 
    TEST_IT (OK <= (status = TIMER_queueTimer(NULL,gTimer2, 10,0)));
     /* This Shoudl Fail  As the No Control Block */ 
    TEST_IT (OK <= (status = TIMER_queueTimer(NULL,gTimer1, 10,0)));

    /* This should work */
    TEST_IT (OK > (status = TIMER_queueTimer(&gCb1,gTimer1, TIMER1_TIMEOUT,0)));
    /* This should work */
    TEST_IT (OK > (status = TIMER_queueTimer(&gCb2,gTimer1, TIMER2_TIMEOUT,0)));

    currentTimeMSInit = RTOS_getUpTimeInMS();
    /* This Should work */
    TEST_IT(OK > (status = TIMER_createTimer(utils_TimeoutCallback2,&gTimer2)));

    /* This Should work */
    TEST_IT (OK > (status = TIMER_queueTimer(&gCb2,gTimer2, TIMER2_TIMEOUT,0)));

    /* This Shoudl Fail */
    TEST_IT(OK <= (status = TIMER_deInitTimer()));

    TEST_IT (OK > (status = TIMER_unTimer(&gCb2,gTimer1)));

    for (i = 0 ; i < 200;i ++)
    {
        RTOS_sleepMS(100);
        TIMER_checkTimer(gTimer1);
        TIMER_checkTimer(gTimer2);
    }

    TEST_IT(OK > (status = TIMER_destroyTimer(gTimer1)));
    TEST_IT(OK > (status = TIMER_destroyTimer(gTimer2)));
    /* This Shoudl Work */
    TEST_IT(OK > (status = TIMER_deInitTimer()));

	/*retVal += UNITTEST_STATUS(i, RADIUS_EXAMPLE_main(0));*/
	
exit:
	return status;

}

