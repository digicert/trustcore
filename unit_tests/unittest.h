/*
 *  unittest.h
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


#ifndef __UNITTEST_HEADER__
#define __UNITTEST_HEADER__

#ifndef __MOC_LINE__
#define __MOC_LINE__ __LINE__
#endif

#if defined( __UNITTEST_REMOTE_SUPPORT__)
#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined( __RTOS_SOLARIS__) || \
    defined(__RTOS_VXWORKS__) || defined( __RTOS_OSX__) || \
    defined(__RTOS_OPENBSD__) || defined( __RTOS_FREEBSD__) || \
    defined(__RTOS_IRIX__) || defined( __RTOS_DUMMY__ ) || \
    defined(__RTOS_SYMBIAN32__)  || defined(__RTOS_WINCE__)
#include <sys/types.h>
#include <sys/socket.h>
#endif
#endif /* __UNITTEST_REMOTE_SUPPORT__ */

extern int remote_target_socket;    /* Needed by tests to determine if the peer IP address should be used of if localhost is acceptable */

/* prototypes */
typedef int (*TestFun)();

int unittest_intEQ(const char* file, int line, const char* testExpr, 
            int hint, int result, int expected);
int unittest_intGE( const char* file, int line, const char* testExpr, 
            int hint, int result, int expected);
int unittest_intNE( const char* file, int line, const char* testExpr, 
            int hint, int result, int expected);

int run_test( const char* testFunName, const char* fileName,
             TestFun testFun, int* pass);

void report( int total, int pass);

/* macros */
/* used by test programs */
#define UNITTEST_TRUE( h, t)     unittest_intNE(__FILE__, __LINE__, #t, (h), (t), 0)
#define UNITTEST_INT( h, t, v)   unittest_intEQ(__FILE__, __LINE__, #t, (h), (t), (v))
#define UNITTEST_STATUS( h, s)   unittest_intGE(__FILE__, __LINE__, #s, (h), (s), OK)
#define UNITTEST_VALIDPTR( h, p) unittest_intNE(__FILE__, __LINE__, #p, (h), (0!=p), 0)

/* UNITTEST_GOTO( TEST_MACRO, testret, exit_label) */
#define UNITTEST_GOTO( T, r, l)  if (T) { ++r; goto l; } 
#define UNITTEST_STATUS_GOTO( h, s, r, l) if (UNITTEST_STATUS(h,s)) { ++r; goto l; }

void unittest_write(const char* msg);

void unittest_write_buffer( const unsigned char* buff, int buffLen);

/* used by drivers */
typedef struct TestDescriptor
{
    int (*testFun)();
    char* testName;
    char* fileName;
} TestDescriptor;

#define TEST_DESC(f, a) { (a), #a, (f) }

int run_test_by_name( const char* name, TestDescriptor* tests, 
                      int num_tests, int* pass, int* total_tests);

int run_test_by_names( const char* names[], int num_names, 
                       TestDescriptor* tests, 
                       int num_tests, int* pass, int* total_tests);

#define RUN_TEST_BY_NAME( n, t, nt, p) run_test_by_name( (n), (t), (nt), (p))
#define RUN_TEST_BY_NAMES( n, nn, t, nt, p, tt) run_test_by_names( (n), (nn), (t), (nt), (p), (tt))
#define RUN_TEST( f, t, p) run_test( #t, (f), (t), (p))

#ifndef __UNITTEST_REMOTE_SUPPORT__
/* baby steps. Define the _H macros to just call the above, or "return" a 0. */
#define CONNECT_TEST_TARGET_H(in,en,ac,av,tm,cf) 0
#define RUN_TEST_BY_NAME_H( c, n, t, nt, p) RUN_TEST_BY_NAME( (n), (t), (nt), (p))
#define RUN_TEST_BY_NAMES_H( c, n, nn, t, nt, p, tt) RUN_TEST_BY_NAMES( (n), (nn), (t), (nt), (p), (tt))
#define RUN_TEST_H( c, f, t, p) RUN_TEST( (f), (t), (p))
#define STOP_TEST_TARGET_H(cf,tm) 0
#define INITCOMM_TGT(hi, cf) 0
#define PROC_RUNTEST_CMDS_TGT(hi, cf, td, nt) 0
#define STOPCOMM_TGT(cf, st) 0
#else
int connect_test_target_h(const char *tgtname, const char *execname,
						  int argc, char* argv[], int timeoutsecs, int *pconnfd);

int stop_test_target_h(int *pconnfd, int timeoutsecs);

int run_test_h( int connfd, const char* testFunName, const char* fileName,
             TestFun testFun, int* pass);

int run_test_by_name_h( int connfd, const char* name, TestDescriptor* tests,
                      int num_tests, int* pass);

int run_test_by_names_h( int connfd, const char* names[], int num_names,
                       TestDescriptor* tests,
                       int num_tests, int* pass);

int initcomm_tgt( struct sockaddr *phostip, int *pconnfd);
int proc_runtest_cmds_tgt( struct sockaddr *phostip, int connfd, TestDescriptor* tests, int num_tests);
int stopcomm_tgt( int *pconnfd, int statusin);

// Real macros used for remote test execution.
// Host side
#define CONNECT_TEST_TARGET_H(in,en,ac,av,tm,cf) connect_test_target_h( (in), (en), (ac), (av), (tm), (cf))
#define RUN_TEST_BY_NAME_H( c, n, t, nt, p) run_test_by_name_h( (c), (n), (t), (nt), (p))
#define RUN_TEST_BY_NAMES_H( c, n, nn, t, nt, p, tt) run_test_by_names_h( (c), (n), (nn), (t), (nt), (p))
#define RUN_TEST_H( c, f, t, p) run_test_h( (c), #t, (f), (t), (p))
#define STOP_TEST_TARGET_H(cf,tm) stop_test_target_h((cf), (tm))
// Target side
#define INITCOMM_TGT(hi, cf) initcomm_tgt( (hi), (cf))
#define PROC_RUNTEST_CMDS_TGT(hi, cf, td, nt) proc_runtest_cmds_tgt( (hi), (cf), (td), (nt))
#define STOPCOMM_TGT(cf, st) stopcomm_tgt((cf), (st))
#endif

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
#define HW_ACCEL_GET_CONTEXT(sb)        \
        sbyte4 sb = UNITTEST_getHwAccelChannel()
#define HW_ACCEL_FREE_CONTEXT(sb)       \
        UNITTEST_releaseHwAccelChannel(sb)
#else                  /* __ENABLE_DIGICERT_HARDWARE_CRYPTO_ACCEL__ */
#define HW_ACCEL_GET_CONTEXT(sb)
#define HW_ACCEL_FREE_CONTEXT(sb)
#endif                  /* __ENABLE_DIGICERT_HARDWARE_CRYPTO_ACCEL__ */


/* FILE_PATH macro for windows CE that does not 
have the concept of "current directory" */
#ifndef FILE_PATH
#ifdef TEST_DIR
#define xstr(m) str(m)
#define str(m)  #m
#define FILE_PATH(a)  xstr(TEST_DIR) a
#else
#define FILE_PATH(a) a
#endif
#endif

void redirectOutput(char *pFile);
void restoreOutput();
#define REDIRECT_OUTPUT(_file)  redirectOutput((char *) _file);
#define RESTORE_OUTPUT          restoreOutput();

#endif








