/* main.c 
*
* test driver generated on 2025-11-18 10:44:32 -0800 
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


/*============./base64m_test.c===========*/

/* found int base64m_test_all(void); ====> function is base64m_test_all */
/* found int base64m_test_url_all(void); ====> function is base64m_test_url_all */
/*==================================*/


/*============./datetime_test.c===========*/

/* found int datetime_test_1(void); ====> function is datetime_test_1 */
/*==================================*/


/*============./dynarray_test.c===========*/

/* found int dynarray_test_1(void); ====> function is dynarray_test_1 */
/*==================================*/


/*============./hash_table_test.c===========*/

/* found int hash_table_test_all(void); ====> function is hash_table_test_all */
/*==================================*/


/*============./instance_test.c===========*/

/*==================================*/


/*============./mbitmap_test.c===========*/

/* found int mbitmap_test_all(void); ====> function is mbitmap_test_all */
/*==================================*/


/*============./mem_part_test.c===========*/

/* found int mem_part_test_all(void); ====> function is mem_part_test_all */
/*==================================*/


/*============./mem_pool_test.c===========*/

/* found int mem_pool_test_trac341(void); ====> function is mem_pool_test_trac341 */
/*==================================*/


/*============./memfile_test.c===========*/

/* found int memfile_test_read(void); ====> function is memfile_test_read */
/*==================================*/


/*============./merrors_test.c===========*/

/* found int merrors_test_all(void); ====> function is merrors_test_all */
/*==================================*/


/*============./mfmgmt_test.c===========*/

/* found int mfmgmt_test(void); ====> function is mfmgmt_test */
/*==================================*/


/*============./mime_parser_test.c===========*/

/* found int mime_parser_test_main(void); ====> function is mime_parser_test_main */
/*==================================*/


/*============./mjson_test.c===========*/

/* found int mjson_test_acquireRelease(void); ====> function is mjson_test_acquireRelease */
/* found int mjson_test_parsePrimitives(void); ====> function is mjson_test_parsePrimitives */
/* found int mjson_test_parseBoundary(void); ====> function is mjson_test_parseBoundary */
/* found int mjson_test_parseSimple(void); ====> function is mjson_test_parseSimple */
/* found int mjson_test_parseSimpleBadInput(void); ====> function is mjson_test_parseSimpleBadInput */
/* found int mjson_test_parseSimpleBoolean(void); ====> function is mjson_test_parseSimpleBoolean */
/* found int mjson_test_parseSimpleNull(void); ====> function is mjson_test_parseSimpleNull */
/* found int mjson_test_parseSimpleStrings(void); ====> function is mjson_test_parseSimpleStrings */
/* found int mjson_test_getTokenBoundary(void); ====> function is mjson_test_getTokenBoundary */
/* found int mjson_test_getTokenEmpty(void); ====> function is mjson_test_getTokenEmpty */
/* found int mjson_test_getTokenSimple(void); ====> function is mjson_test_getTokenSimple */
/* found int mjson_test_parseArray(void); ====> function is mjson_test_parseArray */
/* found int mjson_test_parseNumbers(void); ====> function is mjson_test_parseNumbers */
/* found int mjson_test_parseNumbersBadInput(void); ====> function is mjson_test_parseNumbersBadInput */
/* found int mjson_test_parseObjectElements(void); ====> function is mjson_test_parseObjectElements */
/* found int mjson_test_parseNestedObjects(void); ====> function is mjson_test_parseNestedObjects */
/* found int mjson_test_parseNestedObjectsBadInput(void); ====> function is mjson_test_parseNestedObjectsBadInput */
/* found int mjson_test_getObjectIndexBoundary(void); ====> function is mjson_test_getObjectIndexBoundary */
/* found int mjson_test_getObjectIndexSimple(void); ====> function is mjson_test_getObjectIndexSimple */
/* found int mjson_test_getObjectIndexBoundedSimple(void); ====> function is mjson_test_getObjectIndexBoundedSimple */
/* found int mjson_test_getObjectIndexBounded(void); ====> function is mjson_test_getObjectIndexBounded */
/* found int mjson_test_parseObjectsInArray(void); ====> function is mjson_test_parseObjectsInArray */
/* found int mjson_test_getObjectIndexArray(void); ====> function is mjson_test_getObjectIndexArray */
/* found int mjson_test_getObjectIndexBoundedArray(void); ====> function is mjson_test_getObjectIndexBoundedArray */
/* found int mjson_test_parseNestedArrays(void); ====> function is mjson_test_parseNestedArrays */
/* found int mjson_test_parseJSONExamples(void); ====> function is mjson_test_parseJSONExamples */
/*==================================*/


/*============./moc_segment_test.c===========*/

/* found int moc_segment_test_all(void); ====> function is moc_segment_test_all */
/*==================================*/


/*============./moc_stream_test.c===========*/

/* found int moc_stream_test_all(void); ====> function is moc_stream_test_all */
/*==================================*/


/*============./mprintf_test.c===========*/

/* found int mprintf_test_all(void); ====> function is mprintf_test_all */
/*==================================*/


/*============./mrtos_test.c===========*/

/* found int mrtos_test_time(void); ====> function is mrtos_test_time */
/*==================================*/


/*============./mstdlib_test.c===========*/

/* found int mstdlib_test_all(void); ====> function is mstdlib_test_all */
/* found int mstdlib_test_ctime_match(void); ====> function is mstdlib_test_ctime_match */
/* found int mstdlib_test_bitCount(void); ====> function is mstdlib_test_bitCount */
/* found int mstdlib_test_realloc(void); ====> function is mstdlib_test_realloc */
/*==================================*/


/*============./prime_test.c===========*/

/* found int prime_test_1(void); ====> function is prime_test_1 */
/*==================================*/


/*============./property_test.c===========*/

/* found int property_test(void); ====> function is property_test */
/*==================================*/


/*============./protobuf_test.c===========*/

/* found int protobuf_test_1(void); ====> function is protobuf_test_1 */
/* found int protobuf_test_2(void); ====> function is protobuf_test_2 */
/* found int protobuf_test_3(void); ====> function is protobuf_test_3 */
/* found int protobuf_test_4(void); ====> function is protobuf_test_4 */
/* found int protobuf_test_5(void); ====> function is protobuf_test_5 */
/* found int protobuf_test_bool(void); ====> function is protobuf_test_bool */
/* found int protobuf_test_uint64(void); ====> function is protobuf_test_uint64 */
/* found int protobuf_test_uint32(void); ====> function is protobuf_test_uint32 */
/* found int protobuf_test_int32(void); ====> function is protobuf_test_int32 */
/* found int protobuf_test_encode_empty(void); ====> function is protobuf_test_encode_empty */
/* found int protobuf_test_encode_with_uuid(void); ====> function is protobuf_test_encode_with_uuid */
/* found int protobuf_test_encode_with_body(void); ====> function is protobuf_test_encode_with_body */
/* found int protobuf_test_encode_with_metric(void); ====> function is protobuf_test_encode_with_metric */
/* found int protobuf_test_encode_with_multiple_metrics(void); ====> function is protobuf_test_encode_with_multiple_metrics */
/* found int protobuf_test_encode_with_all_fields(void); ====> function is protobuf_test_encode_with_all_fields */
/*==================================*/


/*============./random_string_test.c===========*/

/* found int random_string_test_1(void); ====> function is random_string_test_1 */
/*==================================*/


/*============./random_test.c===========*/

/* found int random_test_perf_start(void); ====> function is random_test_perf_start */
/* found int random_test_perf_start_fips186(void); ====> function is random_test_perf_start_fips186 */
/* found int random_test_perf_start_any(void); ====> function is random_test_perf_start_any */
/* found int random_test_perf_start_ctr(void); ====> function is random_test_perf_start_ctr */
/*==================================*/


/*============./redblack_test.c===========*/

/* found int redblack_test(void); ====> function is redblack_test */
/*==================================*/


/*============./sort_test.c===========*/

/* found int sort_test(void); ====> function is sort_test */
/*==================================*/


/*============./stack_test.c===========*/

/* found int stack_test_all(void); ====> function is stack_test_all */
/*==================================*/


/*============./timer_test.c===========*/

/* found int timer_test_all(void); ====> function is timer_test_all */
/*==================================*/


/*============./tree_test.c===========*/

/* found int tree_test_1(void); ====> function is tree_test_1 */
/*==================================*/


/*============./uri_test.c===========*/

/* found int uri_test_all(void); ====> function is uri_test_all */
/*==================================*/


/*============./vlong_test.c===========*/

/* found int vlong_test_1(void); ====> function is vlong_test_1 */
/* found int vlong_test_divide(void); ====> function is vlong_test_divide */
/* found int vlong_test_2(void); ====> function is vlong_test_2 */
/* found int vlong_test_dh_random1(void); ====> function is vlong_test_dh_random1 */
/* found int vlong_test_dh_random2(void); ====> function is vlong_test_dh_random2 */
/* found int vlong_test_bitlength(void); ====> function is vlong_test_bitlength */
/* found int vlong_test_perf_init_monty(void); ====> function is vlong_test_perf_init_monty */
/* found int vlong_test_perf_modexp(void); ====> function is vlong_test_perf_modexp */
/* found int vlong_test_barrett_mu(void); ====> function is vlong_test_barrett_mu */
/* found int vlong_test_barrett_reduction(void); ====> function is vlong_test_barrett_reduction */
/* found int vlong_test_barrett_mult(void); ====> function is vlong_test_barrett_mult */
/* found int vlong_test_doublediv(void); ====> function is vlong_test_doublediv */
/* found int vlong_test_shift(void); ====> function is vlong_test_shift */
/* found int vlong_test_shift_bug(void); ====> function is vlong_test_shift_bug */
/* found int vlong_test_cmp(void); ====> function is vlong_test_cmp */
/* found int vlong_test_blinding_factors(void); ====> function is vlong_test_blinding_factors */
/* found int vlong_test_mpint_serialize(void); ====> function is vlong_test_mpint_serialize */
/* found int vlong_test_mpint_serialize_2(void); ====> function is vlong_test_mpint_serialize_2 */
/* found int vlong_test_vlongFromUByte4String(void); ====> function is vlong_test_vlongFromUByte4String */
/* found int vlong_test_modular_inverse(void); ====> function is vlong_test_modular_inverse */
/* found int vlong_test_mod_exp(void); ====> function is vlong_test_mod_exp */
/* found int vlong_test_rho(void); ====> function is vlong_test_rho */
/* found int vlong_test_montgomery_mult_vectors(void); ====> function is vlong_test_montgomery_mult_vectors */
/* found int vlong_test_modular_inverse2(void); ====> function is vlong_test_modular_inverse2 */
/*==================================*/



/* functions in file base64m_test.c */
int base64m_test_all();
int base64m_test_url_all();



/* functions in file datetime_test.c */
int datetime_test_1();



/* functions in file dynarray_test.c */
int dynarray_test_1();



/* functions in file hash_table_test.c */
int hash_table_test_all();



/* functions in file instance_test.c */




/* functions in file mbitmap_test.c */
int mbitmap_test_all();



/* functions in file mem_part_test.c */
int mem_part_test_all();



/* functions in file mem_pool_test.c */
int mem_pool_test_trac341();



/* functions in file memfile_test.c */
int memfile_test_read();



/* functions in file merrors_test.c */
int merrors_test_all();



/* functions in file mfmgmt_test.c */
int mfmgmt_test();



/* functions in file mime_parser_test.c */
int mime_parser_test_main();



/* functions in file mjson_test.c */
int mjson_test_acquireRelease();
int mjson_test_parsePrimitives();
int mjson_test_parseBoundary();
int mjson_test_parseSimple();
int mjson_test_parseSimpleBadInput();
int mjson_test_parseSimpleBoolean();
int mjson_test_parseSimpleNull();
int mjson_test_parseSimpleStrings();
int mjson_test_getTokenBoundary();
int mjson_test_getTokenEmpty();
int mjson_test_getTokenSimple();
int mjson_test_parseArray();
int mjson_test_parseNumbers();
int mjson_test_parseNumbersBadInput();
int mjson_test_parseObjectElements();
int mjson_test_parseNestedObjects();
int mjson_test_parseNestedObjectsBadInput();
int mjson_test_getObjectIndexBoundary();
int mjson_test_getObjectIndexSimple();
int mjson_test_getObjectIndexBoundedSimple();
int mjson_test_getObjectIndexBounded();
int mjson_test_parseObjectsInArray();
int mjson_test_getObjectIndexArray();
int mjson_test_getObjectIndexBoundedArray();
int mjson_test_parseNestedArrays();
int mjson_test_parseJSONExamples();



/* functions in file moc_segment_test.c */
int moc_segment_test_all();



/* functions in file moc_stream_test.c */
int moc_stream_test_all();



/* functions in file mprintf_test.c */
int mprintf_test_all();



/* functions in file mrtos_test.c */
int mrtos_test_time();



/* functions in file mstdlib_test.c */
int mstdlib_test_all();
int mstdlib_test_ctime_match();
int mstdlib_test_bitCount();
int mstdlib_test_realloc();



/* functions in file prime_test.c */
int prime_test_1();



/* functions in file property_test.c */
int property_test();



/* functions in file protobuf_test.c */
int protobuf_test_1();
int protobuf_test_2();
int protobuf_test_3();
int protobuf_test_4();
int protobuf_test_5();
int protobuf_test_bool();
int protobuf_test_uint64();
int protobuf_test_uint32();
int protobuf_test_int32();
int protobuf_test_encode_empty();
int protobuf_test_encode_with_uuid();
int protobuf_test_encode_with_body();
int protobuf_test_encode_with_metric();
int protobuf_test_encode_with_multiple_metrics();
int protobuf_test_encode_with_all_fields();



/* functions in file random_string_test.c */
int random_string_test_1();



/* functions in file random_test.c */
int random_test_perf_start();
int random_test_perf_start_fips186();
int random_test_perf_start_any();
int random_test_perf_start_ctr();



/* functions in file redblack_test.c */
int redblack_test();



/* functions in file sort_test.c */
int sort_test();



/* functions in file stack_test.c */
int stack_test_all();



/* functions in file timer_test.c */
int timer_test_all();



/* functions in file tree_test.c */
int tree_test_1();



/* functions in file uri_test.c */
int uri_test_all();



/* functions in file vlong_test.c */
int vlong_test_1();
int vlong_test_divide();
int vlong_test_2();
int vlong_test_dh_random1();
int vlong_test_dh_random2();
int vlong_test_bitlength();
int vlong_test_perf_init_monty();
int vlong_test_perf_modexp();
int vlong_test_barrett_mu();
int vlong_test_barrett_reduction();
int vlong_test_barrett_mult();
int vlong_test_doublediv();
int vlong_test_shift();
int vlong_test_shift_bug();
int vlong_test_cmp();
int vlong_test_blinding_factors();
int vlong_test_mpint_serialize();
int vlong_test_mpint_serialize_2();
int vlong_test_vlongFromUByte4String();
int vlong_test_modular_inverse();
int vlong_test_mod_exp();
int vlong_test_rho();
int vlong_test_montgomery_mult_vectors();
int vlong_test_modular_inverse2();

TestDescriptor gTestDescs[] = {

	TEST_DESC("base64m_test.c", base64m_test_all),

	TEST_DESC("base64m_test.c", base64m_test_url_all),

	TEST_DESC("datetime_test.c", datetime_test_1),

	TEST_DESC("dynarray_test.c", dynarray_test_1),

	TEST_DESC("hash_table_test.c", hash_table_test_all),

	TEST_DESC("mbitmap_test.c", mbitmap_test_all),

	TEST_DESC("mem_part_test.c", mem_part_test_all),

	TEST_DESC("mem_pool_test.c", mem_pool_test_trac341),

	TEST_DESC("memfile_test.c", memfile_test_read),

	TEST_DESC("merrors_test.c", merrors_test_all),

	TEST_DESC("mfmgmt_test.c", mfmgmt_test),

	TEST_DESC("mime_parser_test.c", mime_parser_test_main),

	TEST_DESC("mjson_test.c", mjson_test_acquireRelease),

	TEST_DESC("mjson_test.c", mjson_test_parsePrimitives),

	TEST_DESC("mjson_test.c", mjson_test_parseBoundary),

	TEST_DESC("mjson_test.c", mjson_test_parseSimple),

	TEST_DESC("mjson_test.c", mjson_test_parseSimpleBadInput),

	TEST_DESC("mjson_test.c", mjson_test_parseSimpleBoolean),

	TEST_DESC("mjson_test.c", mjson_test_parseSimpleNull),

	TEST_DESC("mjson_test.c", mjson_test_parseSimpleStrings),

	TEST_DESC("mjson_test.c", mjson_test_getTokenBoundary),

	TEST_DESC("mjson_test.c", mjson_test_getTokenEmpty),

	TEST_DESC("mjson_test.c", mjson_test_getTokenSimple),

	TEST_DESC("mjson_test.c", mjson_test_parseArray),

	TEST_DESC("mjson_test.c", mjson_test_parseNumbers),

	TEST_DESC("mjson_test.c", mjson_test_parseNumbersBadInput),

	TEST_DESC("mjson_test.c", mjson_test_parseObjectElements),

	TEST_DESC("mjson_test.c", mjson_test_parseNestedObjects),

	TEST_DESC("mjson_test.c", mjson_test_parseNestedObjectsBadInput),

	TEST_DESC("mjson_test.c", mjson_test_getObjectIndexBoundary),

	TEST_DESC("mjson_test.c", mjson_test_getObjectIndexSimple),

	TEST_DESC("mjson_test.c", mjson_test_getObjectIndexBoundedSimple),

	TEST_DESC("mjson_test.c", mjson_test_getObjectIndexBounded),

	TEST_DESC("mjson_test.c", mjson_test_parseObjectsInArray),

	TEST_DESC("mjson_test.c", mjson_test_getObjectIndexArray),

	TEST_DESC("mjson_test.c", mjson_test_getObjectIndexBoundedArray),

	TEST_DESC("mjson_test.c", mjson_test_parseNestedArrays),

	TEST_DESC("mjson_test.c", mjson_test_parseJSONExamples),

	TEST_DESC("moc_segment_test.c", moc_segment_test_all),

	TEST_DESC("moc_stream_test.c", moc_stream_test_all),

	TEST_DESC("mprintf_test.c", mprintf_test_all),

	TEST_DESC("mrtos_test.c", mrtos_test_time),

	TEST_DESC("mstdlib_test.c", mstdlib_test_all),

	TEST_DESC("mstdlib_test.c", mstdlib_test_ctime_match),

	TEST_DESC("mstdlib_test.c", mstdlib_test_bitCount),

	TEST_DESC("mstdlib_test.c", mstdlib_test_realloc),

	TEST_DESC("prime_test.c", prime_test_1),

	TEST_DESC("property_test.c", property_test),

	TEST_DESC("protobuf_test.c", protobuf_test_1),

	TEST_DESC("protobuf_test.c", protobuf_test_2),

	TEST_DESC("protobuf_test.c", protobuf_test_3),

	TEST_DESC("protobuf_test.c", protobuf_test_4),

	TEST_DESC("protobuf_test.c", protobuf_test_5),

	TEST_DESC("protobuf_test.c", protobuf_test_bool),

	TEST_DESC("protobuf_test.c", protobuf_test_uint64),

	TEST_DESC("protobuf_test.c", protobuf_test_uint32),

	TEST_DESC("protobuf_test.c", protobuf_test_int32),

	TEST_DESC("protobuf_test.c", protobuf_test_encode_empty),

	TEST_DESC("protobuf_test.c", protobuf_test_encode_with_uuid),

	TEST_DESC("protobuf_test.c", protobuf_test_encode_with_body),

	TEST_DESC("protobuf_test.c", protobuf_test_encode_with_metric),

	TEST_DESC("protobuf_test.c", protobuf_test_encode_with_multiple_metrics),

	TEST_DESC("protobuf_test.c", protobuf_test_encode_with_all_fields),

	TEST_DESC("random_string_test.c", random_string_test_1),

	TEST_DESC("random_test.c", random_test_perf_start),

	TEST_DESC("random_test.c", random_test_perf_start_fips186),

	TEST_DESC("random_test.c", random_test_perf_start_any),

	TEST_DESC("random_test.c", random_test_perf_start_ctr),

	TEST_DESC("redblack_test.c", redblack_test),

	TEST_DESC("sort_test.c", sort_test),

	TEST_DESC("stack_test.c", stack_test_all),

	TEST_DESC("timer_test.c", timer_test_all),

	TEST_DESC("tree_test.c", tree_test_1),

	TEST_DESC("uri_test.c", uri_test_all),

	TEST_DESC("vlong_test.c", vlong_test_1),

	TEST_DESC("vlong_test.c", vlong_test_divide),

	TEST_DESC("vlong_test.c", vlong_test_2),

	TEST_DESC("vlong_test.c", vlong_test_dh_random1),

	TEST_DESC("vlong_test.c", vlong_test_dh_random2),

	TEST_DESC("vlong_test.c", vlong_test_bitlength),

	TEST_DESC("vlong_test.c", vlong_test_perf_init_monty),

	TEST_DESC("vlong_test.c", vlong_test_perf_modexp),

	TEST_DESC("vlong_test.c", vlong_test_barrett_mu),

	TEST_DESC("vlong_test.c", vlong_test_barrett_reduction),

	TEST_DESC("vlong_test.c", vlong_test_barrett_mult),

	TEST_DESC("vlong_test.c", vlong_test_doublediv),

	TEST_DESC("vlong_test.c", vlong_test_shift),

	TEST_DESC("vlong_test.c", vlong_test_shift_bug),

	TEST_DESC("vlong_test.c", vlong_test_cmp),

	TEST_DESC("vlong_test.c", vlong_test_blinding_factors),

	TEST_DESC("vlong_test.c", vlong_test_mpint_serialize),

	TEST_DESC("vlong_test.c", vlong_test_mpint_serialize_2),

	TEST_DESC("vlong_test.c", vlong_test_vlongFromUByte4String),

	TEST_DESC("vlong_test.c", vlong_test_modular_inverse),

	TEST_DESC("vlong_test.c", vlong_test_mod_exp),

	TEST_DESC("vlong_test.c", vlong_test_rho),

	TEST_DESC("vlong_test.c", vlong_test_montgomery_mult_vectors),

	TEST_DESC("vlong_test.c", vlong_test_modular_inverse2),
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

	retVal += RUN_TEST_H( connfd, "base64m_test.c", base64m_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "base64m_test.c", base64m_test_url_all, &pass);

	retVal += RUN_TEST_H( connfd, "datetime_test.c", datetime_test_1, &pass);

	retVal += RUN_TEST_H( connfd, "dynarray_test.c", dynarray_test_1, &pass);

	retVal += RUN_TEST_H( connfd, "hash_table_test.c", hash_table_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "mbitmap_test.c", mbitmap_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "mem_part_test.c", mem_part_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "mem_pool_test.c", mem_pool_test_trac341, &pass);

	retVal += RUN_TEST_H( connfd, "memfile_test.c", memfile_test_read, &pass);

	retVal += RUN_TEST_H( connfd, "merrors_test.c", merrors_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "mfmgmt_test.c", mfmgmt_test, &pass);

	retVal += RUN_TEST_H( connfd, "mime_parser_test.c", mime_parser_test_main, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_acquireRelease, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parsePrimitives, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseBoundary, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseSimple, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseSimpleBadInput, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseSimpleBoolean, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseSimpleNull, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseSimpleStrings, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getTokenBoundary, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getTokenEmpty, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getTokenSimple, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseArray, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseNumbers, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseNumbersBadInput, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseObjectElements, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseNestedObjects, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseNestedObjectsBadInput, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getObjectIndexBoundary, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getObjectIndexSimple, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getObjectIndexBoundedSimple, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getObjectIndexBounded, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseObjectsInArray, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getObjectIndexArray, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_getObjectIndexBoundedArray, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseNestedArrays, &pass);

	retVal += RUN_TEST_H( connfd, "mjson_test.c", mjson_test_parseJSONExamples, &pass);

	retVal += RUN_TEST_H( connfd, "moc_segment_test.c", moc_segment_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "moc_stream_test.c", moc_stream_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "mprintf_test.c", mprintf_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "mrtos_test.c", mrtos_test_time, &pass);

	retVal += RUN_TEST_H( connfd, "mstdlib_test.c", mstdlib_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "mstdlib_test.c", mstdlib_test_ctime_match, &pass);

	retVal += RUN_TEST_H( connfd, "mstdlib_test.c", mstdlib_test_bitCount, &pass);

	retVal += RUN_TEST_H( connfd, "mstdlib_test.c", mstdlib_test_realloc, &pass);

	retVal += RUN_TEST_H( connfd, "prime_test.c", prime_test_1, &pass);

	retVal += RUN_TEST_H( connfd, "property_test.c", property_test, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_1, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_2, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_3, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_4, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_5, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_bool, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_uint64, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_uint32, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_int32, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_encode_empty, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_encode_with_uuid, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_encode_with_body, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_encode_with_metric, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_encode_with_multiple_metrics, &pass);

	retVal += RUN_TEST_H( connfd, "protobuf_test.c", protobuf_test_encode_with_all_fields, &pass);

	retVal += RUN_TEST_H( connfd, "random_string_test.c", random_string_test_1, &pass);

	retVal += RUN_TEST_H( connfd, "random_test.c", random_test_perf_start, &pass);

	retVal += RUN_TEST_H( connfd, "random_test.c", random_test_perf_start_fips186, &pass);

	retVal += RUN_TEST_H( connfd, "random_test.c", random_test_perf_start_any, &pass);

	retVal += RUN_TEST_H( connfd, "random_test.c", random_test_perf_start_ctr, &pass);

	retVal += RUN_TEST_H( connfd, "redblack_test.c", redblack_test, &pass);

	retVal += RUN_TEST_H( connfd, "sort_test.c", sort_test, &pass);

	retVal += RUN_TEST_H( connfd, "stack_test.c", stack_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "timer_test.c", timer_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "tree_test.c", tree_test_1, &pass);

	retVal += RUN_TEST_H( connfd, "uri_test.c", uri_test_all, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_1, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_divide, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_2, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_dh_random1, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_dh_random2, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_bitlength, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_perf_init_monty, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_perf_modexp, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_barrett_mu, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_barrett_reduction, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_barrett_mult, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_doublediv, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_shift, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_shift_bug, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_cmp, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_blinding_factors, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_mpint_serialize, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_mpint_serialize_2, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_vlongFromUByte4String, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_modular_inverse, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_mod_exp, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_rho, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_montgomery_mult_vectors, &pass);

	retVal += RUN_TEST_H( connfd, "vlong_test.c", vlong_test_modular_inverse2, &pass);
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

