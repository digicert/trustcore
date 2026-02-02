/*
 *  unittest.c
 * 
 *   unit test support
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "unittest.h"
#include "unittest_remote.h"
#include "../src/common/mtypes.h"
    
#if (defined(WIN32) && defined(_DEBUG))
#include <CrtDbg.h>
#endif

#include <assert.h>
#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined( __RTOS_SOLARIS__) || \
    defined(__RTOS_VXWORKS__) || defined( __RTOS_OSX__) || \
    defined(__RTOS_OPENBSD__) || defined( __RTOS_FREEBSD__) || \
    defined(__RTOS_IRIX__) || defined( __RTOS_DUMMY__ ) || \
    defined(__RTOS_SYMBIAN32__)  || defined(__RTOS_WINCE__) || \
    defined(__RTOS_QNX__)
#include <stdio.h>
#define PRINTF      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#endif

/************************************
// Test execution debug-io support.
*************************************/
#define UT_DBG_COMM_HIGH_V   1 /* 0 = OFF 1 = ON */


/*-------------------------------------------------------------------------*/
#ifdef __UNITTEST_REMOTE_SUPPORT__


#define UT_DEBUG_PRINT(t,b,c) ut_debug_print(__FILE__, __LINE__, t, b, c)
static void ut_debug_print(const char* pfile, int iline, int printthis, char *str1, char *str2)
{
    char *pNull = "null";
    if (printthis == 0)
        return;
    if (!str1) str1 = pNull;
    if (!str2) str2 = pNull;
    printf("%s : %d : %s%s\n",pfile,iline,str1,str2);
    
}

#define MAX_DEBUGMSG_SIZE (4*1024)
char debugmsg_spot[MAX_DEBUGMSG_SIZE];
#endif /* __UNITTEST_REMOTE_SUPPORT__ */

int remote_target_socket = 0;	/* Needed by tests to determine if the peer IP address should be used of if localhost is acceptable */

int unittest_intEQ(const char* file, int line, const char* test, 
                int hint, int result, int expected)
{
#ifndef __UNITTEST_REMOTE_SUPPORT__

    if ( result != expected)
    {
        PRINTF("%s:%d:Test %s (%d) (%08x) result = %d, expected = %d\n", 
            file, line, test, hint, hint, result, expected);
        return 1;
    }
    return 0;
#else
    if ( result != expected)
    {
        sprintf(debugmsg_spot,"%s:%d:Test %s (%d) (%08x) result = %d, expected = %d\n",
            file, line, test, hint, hint, result, expected);
        unittest_write(debugmsg_spot);
        return 1;
    }
    return 0;
#endif
}


/*-------------------------------------------------------------------------*/

int unittest_intNE(const char* file, int line, const char* test, 
                int hint, int result, int unExpected)
{
#ifndef __UNITTEST_REMOTE_SUPPORT__
    if ( result == unExpected)
    {
        PRINTF("%s:%d:Test %s (%d)(%08x) result = %d, expected != %d\n",
            file, line, test, hint, hint, result, unExpected);
        return 1;
    }
    return 0;
#else
    if ( result == unExpected)
    {
        sprintf(debugmsg_spot,"%s:%d:Test %s (%d)(%08x) result = %d, expected != %d\n",
            file, line, test, hint, hint, result, unExpected);
        unittest_write(debugmsg_spot);
        return 1;
    }
    return 0;
#endif

}


/*-------------------------------------------------------------------------*/

int unittest_intGE( const char* file, int line, const char* testExpr, 
            int hint, int result, int expected)
{
#ifndef __UNITTEST_REMOTE_SUPPORT__
   if ( result < expected)
    {
        PRINTF("%s:%d:Test %s (%d)(%08x) result = %d, expected >= %d\n", 
            file, line, testExpr, hint, hint, result, expected);
        return 1;
    }
    return 0;
#else
    if ( result < expected)
     {
        sprintf(debugmsg_spot,"%s:%d:Test %s (%d)(%08x) result = %d, expected >= %d\n",
             file, line, testExpr, hint, hint, result, expected);
        unittest_write(debugmsg_spot);
         return 1;
     }
     return 0;
#endif
}


/*-------------------------------------------------------------------------*/

void unittest_write(const char* msg)
{
#ifndef __UNITTEST_REMOTE_SUPPORT__
    PRINTF("%s",msg);
#else
    if (remote_target_socket == 0)
    {
    	/* Host side. */
        PRINTF("%s",msg);
    }
    else
    {
    	/* Target side. */
        ut_write_output_cmd_tgt(remote_target_socket, msg);
    }
#endif
}


/*-------------------------------------------------------------------------*/

char* addhexChar( char* out, const unsigned char c)
{
    int n = (c >> 4) & 0x0F;
    *out++ = (char) ( (n < 0xA) ? '0' + n : 'A' + n - 0x0A);
    n = c & 0xF;
    *out++ =  (char) ( (n < 0xA) ? '0' + n : 'A' + n - 0x0A);
    return out;
}

/*-------------------------------------------------------------------------*/

void unittest_write_buffer( const unsigned char* buff, int buffLen)
{
    char line[82];
    line[80] = '\n';
    line[81] = 0;
    /* 6 groups of 8 hex + space = 54 +
       1 group of 24 chars = 24 -> 78 chars */

    while (buffLen)
    {
        char* out = line;
        int i, maxChars = ( buffLen > 24) ? 24 : buffLen;

        out = line;
        for (i = 0; i < maxChars; ++i)
        {
            out = addhexChar(out, buff[i]);
            if (i % 4 == 3)
            {
                *out++ = ' ';
            }
        }
        while (out != line +54)
        {
            *out++ = ' ';
        }

        for (i = 0; i < maxChars; ++i)
        {
            char c = buff[i];
            *out++ = (c >= 0x20 && c <= 0x7E) ? c : '.';
        }
        while (out != line + 80)
        {
            *out++ = ' ';
        }

        unittest_write(line);

        buff += maxChars;
        buffLen -= maxChars;
        
    }
}


/*-------------------------------------------------------------------------*/

int run_test( const char* testFunName, const char* fileName,
             TestFun testFun, int* pass)
{
    int retVal;

    
#if (defined(WIN32) && defined(_DEBUG))
    _CrtMemState memState;
    /* Get current flag */
    int tmpFlag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
    /* Turn on extensive checks */
    tmpFlag |= (_CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_LEAK_CHECK_DF);

    /* Set flag to the new value */
    _CrtSetDbgFlag( tmpFlag );
   _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_DEBUG );
   _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG );
   _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_DEBUG );

   _CrtMemCheckpoint( &memState);

#endif
    
    PRINTF("Running test %s in file %s\n", testFunName, fileName);
#ifndef __RTOS_QNX__
    fflush(stdout);
#endif
    retVal = testFun();
#if (defined(WIN32) && defined(_DEBUG))
    if (!_CrtCheckMemory()) ++retVal;
    _CrtMemDumpAllObjectsSince(&memState);
#endif
    if ( 0==retVal)
    {
        PRINTF("%s: Pass\n\n", testFunName);
        ++(*pass);
    }
    else
    {
        PRINTF("%s: Fail: %d error(s)\n\n", testFunName, retVal);
    }
#ifndef __RTOS_QNX__
    fflush(stdout);
#endif

    return retVal;
}


/*-------------------------------------------------------------------------*/

void report( int total, int pass)
{
    PRINTF(  "\nPass:        %d", pass);
    PRINTF(  "\nFail:        %d", total - pass);
    PRINTF(  "\nTotal tests: %d\n", total);
}


/*-------------------------------------------------------------------------*/

int run_test_by_name( const char* name, TestDescriptor* tests, 
                      int num_tests, int* pass, int* total_tests)
{
    int retVal = 0;
    int i, j, name_len;
    const char* p;

    name_len = 0;
    p = name;

    while (*p) { ++name_len; ++p; }
    if (name_len)
    {
        for (i = 0; i < num_tests; ++i)
        {
            const char* testName;

            testName = tests[i].testName;

            for (j = 0; j < name_len; ++j)
            {
                if (testName[j] != name[j])
                {
                    break;
                }
            }
            if ( name_len == j) /* match */
            {
                (*total_tests)++;
                retVal += run_test(tests[i].testName, tests[i].fileName,
                                   tests[i].testFun, pass);
            }
        }
    }
    return retVal;
}


/*-------------------------------------------------------------------------*/

int list_test_names( TestDescriptor* tests, int num_tests)
{
    int i;

    PRINTF("Available tests:\n\n");
    for (i = 0; i < num_tests; ++i)
    {
        PRINTF("%s",tests[i].testName);
        PRINTF("\n");
    }

    return 0;
}


/*-------------------------------------------------------------------------*/

int run_test_by_names( const char* names[], int num_names, 
                       TestDescriptor* tests, int num_tests, 
                       int* pass, int* total_tests)
{
    int retVal = 0;
    int i;
    
    if (1 == num_names)
    {
        const char* option = names[0];

        if ('-' == option[0]  && 'h' == option[1]  && 0 == option[2] )
        {
            list_test_names(tests, num_tests);
            return 0;
        } 
    }

    for (i = 0; i < num_names; ++i)
    {
        retVal += run_test_by_name( names[i], tests, num_tests, pass, 
                                    total_tests);
    }
    return retVal;
}


#if 0
/* Disable until testmonkey infrastructure could be fixed to handle option
  flags
*/
#include "../src/common/moptions.h"
#include "../src/crypto/hw_accel.h"
#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
static int utest_hwAccelCtx  = 0;
static int hwAccelRefCount = 0;

int
UNITTEST_getHwAccelChannel(void)
{
    if (0 == utest_hwAccelCtx) {
        HARDWARE_ACCEL_OPEN_CHANNEL(9, &utest_hwAccelCtx);
    }
exit:
    assert(utest_hwAccelCtx != 0);
    return utest_hwAccelCtx;
}

void
UNITTEST_releaseHwAccelChannel(int hwAccelCtx)
{
}
#endif
#endif

#ifdef __UNITTEST_REMOTE_SUPPORT__

/*********************************
 Real remote support.
************************************/
int connect_test_target_h(const char *tgtname, const char *execname,
						  int argc, char* argv[], int timeoutsecs, int *pconnfd)
{
	int rc = 0;
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"connect_test_target_h: target name=",tgtname);

    *pconnfd = 0;

    remote_target_socket = 0; /* Host side doesn't use one. */

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"connect_test_target_h: "," Load test target.");
	rc = ut_load_test_target_h(tgtname, execname, argc, argv, timeoutsecs);  /* May exec on localhost, may be a nop. */

	if (rc == 0)
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"connect_test_target_h: "," Connect test target.");
		rc = ut_connect_test_target_h(tgtname, execname, argc, argv, timeoutsecs, pconnfd); /* Connect via socket. */
	}

	if (rc == 0)
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"connect_test_target_h: "," Do Startup cmd.");
		rc = ut_startup_cmd_h(*pconnfd);
	}

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"connect_test_target_h"," done.");
	return rc;
}

int stop_test_target_h(int *pconnfd, int timeoutsecs)
{
	int rc = -1;
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"stop_test_target_h"," ...");
    if (*pconnfd != 0)
    {
    	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"stop_test_target_h"," Sending shutdown cmd.");
    	rc = ut_shutdown_cmd_h(*pconnfd, timeoutsecs); /* Send Shutdown cmd and wait for ACK. */

    	rc = ut_disconnect_test_target_h(pconnfd); /* Closes socket. */
    }

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"stop_test_target_h"," done.");
	return rc;
}

int run_test_h( int connfd, const char* testFunName, const char* fileName,
             TestFun testFun, int* pass)
{
	int rc = -1;
	int retVal = 0;

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"run_test_h"," ...");
    if (connfd != 0)
    {
	    PRINTF("Remotely Running test %s in file %s\n", testFunName, fileName);
    	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"run_test_h"," Sending run_test cmd.");
    	rc = ut_runtest_cmd_h(connfd, testFunName, fileName, &retVal); /* Send RUNTEST cmd, and wait until _FINISHED received.*/
    }

    if ((0==retVal) && (0==rc))
    {
        PRINTF("%s: Pass\n\n", testFunName);
        ++(*pass);
    }
    else
    {
    	if (rc != 0)
    	{
    		retVal = rc; /* This is to catch comm errors.*/
    	}
        PRINTF("%s: Fail: %d error(s)\n\n", testFunName, retVal);
    }

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"run_test_h"," done.");
  	return retVal;

}

int run_test_by_name_h( int connfd, const char* name, TestDescriptor* tests,
                      int num_tests, int* pass)
{
	int index = -1;
	int retVal = 0;
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"run_test_by_name_h"," ...");

	index = ut_testindexfromstr(tests, num_tests, name);
	if (index >= 0)
	{
		retVal += run_test_h(connfd, tests[index].testName, tests[index].fileName,
	                         tests[index].testFun, pass);
	}
	else
	{
        PRINTF("%s: Fail: Test not found.\n", name);
	}

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"run_test_by_name_h"," done.");
  	return 0;
}

int run_test_by_names_h( int connfd, const char* names[], int num_names,
                       TestDescriptor* tests,
                       int num_tests, int* pass)
{
    int retVal = 0;
    int i;

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"run_test_by_names_h"," ...");
    if (1 == num_names)
    {
        const char* option = names[0];

        if ('-' == option[0]  && 'h' == option[1]  && 0 == option[2] )
        {
            list_test_names(tests, num_tests);
            return 0;
        }
    }

    for (i = 0; i < num_names; ++i)
    {
        retVal += run_test_by_name_h(connfd, names[i], tests, num_tests, pass);
    }

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"run_test_by_names_h"," done.");
    return retVal;

}


int initcomm_tgt( struct sockaddr *phostip, int *pconnfd)
{
	int rc;

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"initcomm_tgt"," ...");
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"initcomm_tgt"," Accept incoming connect.");

	remote_target_socket = 0; /* Target side I/O needs this. But default to Zero... */

    rc = ut_initcomm_tgt(phostip, pconnfd);  /* Listen for incoming connections, and accept, returning connected socket. */
    if (rc == 0)
    {
    	remote_target_socket = *pconnfd; /* Target side I/O needs this.*/

    	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"initcomm_tgt"," Wait for startup cmd.");
    	rc = ut_waitfor_startup_cmd_tgt(*pconnfd);
    }

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"initcomm_tgt"," done.");
	return rc;
}

int proc_runtest_cmds_tgt( struct sockaddr *phostip, int connfd, TestDescriptor* tests, int num_tests)
{
	int rc;
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"proc_runtest_cmds_tgt"," ...");
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"proc_runtest_cmds_tgt"," Wait for runtest cmds.");
	rc = ut_waitfor_runtest_cmd_tgt(connfd, tests, num_tests);
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"proc_runtest_cmds_tgt"," done.");
    return rc;
}

int stopcomm_tgt( int *pconnfd, int statusin)
{
	int rc;
	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"stopcomm_tgt"," ...");

	rc = ut_stopcomm_tgt(pconnfd, statusin);

    remote_target_socket = 0; /* Target side I/O needs this. But default to Zero... */

	UT_DEBUG_PRINT(UT_DBG_COMM_HIGH_V,"stopcomm_tgt"," done.");
	return rc;
}

#endif  /*  __UNITTEST_REMOTE_SUPPORT__ */

#if defined(__ENABLE_DIGICERT_UNITTEST__)

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

char *gpOutFile[256];
int gOutFD;
int stdoutFD;

void redirectOutput(char *pFile)
{
    fflush(NULL);
    memcpy(gpOutFile, pFile, strlen(pFile));
    gpOutFile[strlen(pFile)] = '\0';
    stdoutFD = dup(1);
    gOutFD = open(pFile, O_CREAT|O_WRONLY|O_TRUNC, 0666);
    dup2(gOutFD, 1);
}

void restoreOutput()
{
    fflush(NULL);
    dup2(stdoutFD, 1);
    close(stdoutFD);
}

#endif /* __ENABLE_DIGICERT_UNITTEST__ */