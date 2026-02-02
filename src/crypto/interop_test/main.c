/* main.c 
*
* test driver generated on 2024-10-28 19:03:21 +0000 
*/

#if defined(__RTOS_WIN32__)
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#endif
#ifdef __UNITTEST_REMOTE_SUPPORT__
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include "../../../unit_tests/unittest.h"


/*============./pqc_slhdsa_test.c===========*/

/* found int pqc_slhdsa_test_all(void); ====> function is pqc_slhdsa_test_all */
/*==================================*/


/*============./pqc_mldsa_test.c===========*/

/* found int pqc_mldsa_test_all(void); ====> function is pqc_mldsa_test_all */
/*==================================*/


/*============./pqc_mlkem_test.c===========*/

/* found int pqc_mlkem_test_all(void); ====> function is pqc_mlkem_test_all */
/*==================================*/



/* functions in file pqc_slhdsa_test.c */
int pqc_slhdsa_test_all();



/* functions in file pqc_mldsa_test.c */
int pqc_mldsa_test_all();



/* functions in file pqc_mlkem_test.c */
int pqc_mlkem_test_all();

TestDescriptor gTestDescs[] = {

	TEST_DESC("pqc_slhdsa_test.c", pqc_slhdsa_test_all),

	TEST_DESC("pqc_mldsa_test.c", pqc_mldsa_test_all),

	TEST_DESC("pqc_mlkem_test.c", pqc_mlkem_test_all),
};

#define SECS_TO_WAIT_FOR_TARGET 60
int main_host(int argc, char* argv[])
{
  int retVal = 0;
  int pass = 0;
  int connfd = 0;
  int totalTests = sizeof(gTestDescs)/sizeof(gTestDescs[0]) ;

  retVal = CONNECT_TEST_TARGET_H("localhost", "test", argc, argv, SECS_TO_WAIT_FOR_TARGET, &connfd);
  if (retVal != 0)
      return retVal;

  if ( argc > 1)
  {
     totalTests = 0;
     retVal = RUN_TEST_BY_NAMES_H( connfd, (const char**)argv+1, argc-1, gTestDescs,
              sizeof(gTestDescs)/sizeof(gTestDescs[0]), &pass, &totalTests);
  } else
  {

	retVal += RUN_TEST_H( connfd, "pqc_slhdsa_test.c", pqc_slhdsa_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "pqc_mldsa_test.c", pqc_mldsa_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "pqc_mlkem_test.c", pqc_mlkem_test_all, &pass);
  }

  STOP_TEST_TARGET_H(&connfd, 1);

  report(totalTests, pass);
  return retVal;
}

#ifdef __UNITTEST_REMOTE_RUNTARGET__
int main_target(int argc, char* argv[])
{
  int retVal = 0;
  int connfd = 0;
  struct sockaddr hostip = { 0 };

  retVal = INITCOMM_TGT(&hostip, &connfd);
  if (retVal != 0)
      return retVal;

  retVal = PROC_RUNTEST_CMDS_TGT(&hostip, connfd, gTestDescs, sizeof(gTestDescs)/sizeof(gTestDescs[0]) );

  STOPCOMM_TGT(&connfd, retVal);

  return retVal;
}
#endif

int main(int argc, char* argv[])
{

#ifdef __UNITTEST_REMOTE_RUNTARGET__
  return main_target(argc,argv); /* run the Target. */
#else
  return main_host(argc,argv); /* run the Host. */
#endif

}

