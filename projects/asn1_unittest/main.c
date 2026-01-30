/* main.c 
*
* test driver generated on 2025-11-18 10:48:54 -0800 
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


/*============./derencoder_test.c===========*/

/* found int derencoder_test_time(void); ====> function is derencoder_test_time */
/* found int derencoder_test_opaque_test1(void); ====> function is derencoder_test_opaque_test1 */
/* found int derencoder_test_GetIntegerEncodingOffset(void); ====> function is derencoder_test_GetIntegerEncodingOffset */
/* found int derencoder_test_BER1(void); ====> function is derencoder_test_BER1 */
/* found int derencoder_test_BER2(void); ====> function is derencoder_test_BER2 */
/* found int derencoder_test_BER3(void); ====> function is derencoder_test_BER3 */
/* found int derencoder_test_AddIntegerCopyData(void); ====> function is derencoder_test_AddIntegerCopyData */
/* found int derencoder_test_BER4(void); ====> function is derencoder_test_BER4 */
/* found int derencoder_test_BER5(void); ====> function is derencoder_test_BER5 */
/*==================================*/


/*============./mocdecode_test.c===========*/

/* found int mocdecode_test_MAsn1Element_simpleInteger(void); ====> function is mocdecode_test_MAsn1Element_simpleInteger */
/* found int mocdecode_test_MAsn1Element_indefiniteInteger(void); ====> function is mocdecode_test_MAsn1Element_indefiniteInteger */
/* found int mocdecode_test_MAsn1Element_indefiniteDefiniteInput(void); ====> function is mocdecode_test_MAsn1Element_indefiniteDefiniteInput */
/* found int mocdecode_test_MAsn1Element_simpleOID(void); ====> function is mocdecode_test_MAsn1Element_simpleOID */
/* found int mocdecode_test_MAsn1Element_indefiniteOIDString(void); ====> function is mocdecode_test_MAsn1Element_indefiniteOIDString */
/* found int mocdecode_test_MAsn1Element_simpleIA5(void); ====> function is mocdecode_test_MAsn1Element_simpleIA5 */
/* found int mocdecode_test_MAsn1Element_Sequence(void); ====> function is mocdecode_test_MAsn1Element_Sequence */
/* found int mocdecode_test_MAsn1Element_Set(void); ====> function is mocdecode_test_MAsn1Element_Set */
/* found int mocdecode_test_MAsn1Element_SetOf(void); ====> function is mocdecode_test_MAsn1Element_SetOf */
/* found int mocdecode_test_MAsn1Element_IndefiniteSetOf(void); ====> function is mocdecode_test_MAsn1Element_IndefiniteSetOf */
/* found int mocdecode_test_MAsn1Element_IndefiniteOctetOf(void); ====> function is mocdecode_test_MAsn1Element_IndefiniteOctetOf */
/* found int mocdecode_test_MAsn1Element_IndefiniteOctetOfChunked(void); ====> function is mocdecode_test_MAsn1Element_IndefiniteOctetOfChunked */
/* found int mocdecode_test_MAsn1Element_Explicit(void); ====> function is mocdecode_test_MAsn1Element_Explicit */
/* found int mocdecode_test_MAsn1Element_ExplicitUpdate(void); ====> function is mocdecode_test_MAsn1Element_ExplicitUpdate */
/* found int mocdecode_test_MAsn1Element_ExplicitIndefUpdate(void); ====> function is mocdecode_test_MAsn1Element_ExplicitIndefUpdate */
/* found int mocdecode_test_MAsn1Element_indefiniteExplicit(void); ====> function is mocdecode_test_MAsn1Element_indefiniteExplicit */
/* found int mocdecode_test_MAsn1Element_IndefExplicitIndefUpdateSample(void); ====> function is mocdecode_test_MAsn1Element_IndefExplicitIndefUpdateSample */
/* found int mocdecode_test_MAsn1Element_ExplicitIndefUpdateSample(void); ====> function is mocdecode_test_MAsn1Element_ExplicitIndefUpdateSample */
/* found int mocdecode_test_MAsn1Element_ExplicitUpdateSample(void); ====> function is mocdecode_test_MAsn1Element_ExplicitUpdateSample */
/* found int mocdecode_test_MAsn1Element_ExplicitIndefEncodingSample(void); ====> function is mocdecode_test_MAsn1Element_ExplicitIndefEncodingSample */
/* found int mocdecode_test_MAsn1Element_indefiniteChunkedExplicit(void); ====> function is mocdecode_test_MAsn1Element_indefiniteChunkedExplicit */
/* found int mocdecode_test_MAsn1Element_SetOfExplicit(void); ====> function is mocdecode_test_MAsn1Element_SetOfExplicit */
/* found int mocdecode_test_MAsn1Element_indefiniteSetOfExplicit(void); ====> function is mocdecode_test_MAsn1Element_indefiniteSetOfExplicit */
/* found int mocdecode_test_MAsn1Element_definiteSetOfExplicit(void); ====> function is mocdecode_test_MAsn1Element_definiteSetOfExplicit */
/* found int mocdecode_test_MAsn1Element_CMSEnvelopeSample(void); ====> function is mocdecode_test_MAsn1Element_CMSEnvelopeSample */
/* found int mocdecode_test_MAsn1Element_CMSEnvelopeChunkOctetSample(void); ====> function is mocdecode_test_MAsn1Element_CMSEnvelopeChunkOctetSample */
/* found int mocdecode_test_MAsn1Element_indefiniteChunkedSetOfExplicit(void); ====> function is mocdecode_test_MAsn1Element_indefiniteChunkedSetOfExplicit */
/* found int mocdecode_test_MAsn1Element_ConstructedTag(void); ====> function is mocdecode_test_MAsn1Element_ConstructedTag */
/* found int mocdecode_test_MAsn1Element_DataTag(void); ====> function is mocdecode_test_MAsn1Element_DataTag */
/* found int mocdecode_test_MAsn1Element_indefOctet(void); ====> function is mocdecode_test_MAsn1Element_indefOctet */
/* found int mocdecode_test_MAsn1Element_indefOctetChunked(void); ====> function is mocdecode_test_MAsn1Element_indefOctetChunked */
/* found int mocdecode_test_Signature(void); ====> function is mocdecode_test_Signature */
/* found int mocdecode_test_NestedDecoding(void); ====> function is mocdecode_test_NestedDecoding */
/* found int mocdecode_test_ChunkedDecoding(void); ====> function is mocdecode_test_ChunkedDecoding */
/* found int mocdecode_test_CA_ChunkedDecoding(void); ====> function is mocdecode_test_CA_ChunkedDecoding */
/*==================================*/


/*============./mocencode_test.c===========*/

/* found int mocencode_test_MAsn1Element_simpleInteger(void); ====> function is mocencode_test_MAsn1Element_simpleInteger */
/* found int mocencode_test_MAsn1Element_simpleIntegerAlloc(void); ====> function is mocencode_test_MAsn1Element_simpleIntegerAlloc */
/* found int mocencode_test_MAsn1Element_updateInteger(void); ====> function is mocencode_test_MAsn1Element_updateInteger */
/* found int mocencode_test_MAsn1Element_updateIntegerIndef(void); ====> function is mocencode_test_MAsn1Element_updateIntegerIndef */
/* found int mocencode_test_MAsn1Element_simpleOID(void); ====> function is mocencode_test_MAsn1Element_simpleOID */
/* found int mocencode_test_MAsn1Element_updateSingleEncodedIndef(void); ====> function is mocencode_test_MAsn1Element_updateSingleEncodedIndef */
/* found int mocencode_test_MAsn1Element_updateSingleEncodedForcedIndef(void); ====> function is mocencode_test_MAsn1Element_updateSingleEncodedForcedIndef */
/* found int mocencode_test_MAsn1Element_updateMultipleEncodedIndef(void); ====> function is mocencode_test_MAsn1Element_updateMultipleEncodedIndef */
/* found int mocencode_test_MAsn1Element_updateEncodedSampleTest(void); ====> function is mocencode_test_MAsn1Element_updateEncodedSampleTest */
/* found int mocencode_test_MAsn1Element_updateEncoded(void); ====> function is mocencode_test_MAsn1Element_updateEncoded */
/* found int mocencode_test_MAsn1Element_updateEncodedExplicit(void); ====> function is mocencode_test_MAsn1Element_updateEncodedExplicit */
/* found int mocencode_test_MAsn1Element_updateEncodedIndefExplicit(void); ====> function is mocencode_test_MAsn1Element_updateEncodedIndefExplicit */
/* found int mocencode_test_MAsn1Element_updateEncodedExplicitWithOptional(void); ====> function is mocencode_test_MAsn1Element_updateEncodedExplicitWithOptional */
/* found int mocencode_test_MAsn1Element_encodedSETOFMultiple(void); ====> function is mocencode_test_MAsn1Element_encodedSETOFMultiple */
/* found int mocencode_test_MAsn1Element_updateEncodedIndefOption0(void); ====> function is mocencode_test_MAsn1Element_updateEncodedIndefOption0 */
/* found int mocencode_test_MAsn1Element_updateEncodedIndefOption1(void); ====> function is mocencode_test_MAsn1Element_updateEncodedIndefOption1 */
/*==================================*/


/*============./parseasn1_test.c===========*/

/* found int parseasn1_test_resume(void); ====> function is parseasn1_test_resume */
/* found int parseasn1_test_bit_by_bit(void); ====> function is parseasn1_test_bit_by_bit */
/* found int parseasn1_test_simple(void); ====> function is parseasn1_test_simple */
/* found int parseasn1_test_getdata(void); ====> function is parseasn1_test_getdata */
/* found int parseasn1_test_getnth_child(void); ====> function is parseasn1_test_getnth_child */
/*==================================*/


/*============./parsecert_test.c===========*/

/* found int parsecert_test_extractDistinguishedName(void); ====> function is parsecert_test_extractDistinguishedName */
/* found int parsecert_test_extractDates(void); ====> function is parsecert_test_extractDates */
/* found int parsecert_test_enumCRL(void); ====> function is parsecert_test_enumCRL */
/* found int parsecert_test_enumAltName(void); ====> function is parsecert_test_enumAltName */
/* found int parsecert_test_matchCommonName(void); ====> function is parsecert_test_matchCommonName */
/* found int parsecert_test_rsaSignAlgoExtraction(void); ====> function is parsecert_test_rsaSignAlgoExtraction */
/* found int parsecert_test_verifyTimes(void); ====> function is parsecert_test_verifyTimes */
/* found int parsecert_test_verifyCerts(void); ====> function is parsecert_test_verifyCerts */
/* found int parsecert_test_stream(void); ====> function is parsecert_test_stream */
/* found int parsecert_test_rootCerts(void); ====> function is parsecert_test_rootCerts */
/* found int parsecert_test_altSubjectNames(void); ====> function is parsecert_test_altSubjectNames */
/* found int parsecert_test_keyUsageCerts(void); ====> function is parsecert_test_keyUsageCerts */
/* found int parsecert_test_keyUsageValueCerts(void); ====> function is parsecert_test_keyUsageValueCerts */
/* found int parsecert_test_CSR(void); ====> function is parsecert_test_CSR */
/* found int parsecert_test_san_ipv4(void); ====> function is parsecert_test_san_ipv4 */
/* found int parsecert_test_san_ipv6(void); ====> function is parsecert_test_san_ipv6 */
/*==================================*/



/* functions in file derencoder_test.c */
int derencoder_test_time();
int derencoder_test_opaque_test1();
int derencoder_test_GetIntegerEncodingOffset();
int derencoder_test_BER1();
int derencoder_test_BER2();
int derencoder_test_BER3();
int derencoder_test_AddIntegerCopyData();
int derencoder_test_BER4();
int derencoder_test_BER5();



/* functions in file mocdecode_test.c */
int mocdecode_test_MAsn1Element_simpleInteger();
int mocdecode_test_MAsn1Element_indefiniteInteger();
int mocdecode_test_MAsn1Element_indefiniteDefiniteInput();
int mocdecode_test_MAsn1Element_simpleOID();
int mocdecode_test_MAsn1Element_indefiniteOIDString();
int mocdecode_test_MAsn1Element_simpleIA5();
int mocdecode_test_MAsn1Element_Sequence();
int mocdecode_test_MAsn1Element_Set();
int mocdecode_test_MAsn1Element_SetOf();
int mocdecode_test_MAsn1Element_IndefiniteSetOf();
int mocdecode_test_MAsn1Element_IndefiniteOctetOf();
int mocdecode_test_MAsn1Element_IndefiniteOctetOfChunked();
int mocdecode_test_MAsn1Element_Explicit();
int mocdecode_test_MAsn1Element_ExplicitUpdate();
int mocdecode_test_MAsn1Element_ExplicitIndefUpdate();
int mocdecode_test_MAsn1Element_indefiniteExplicit();
int mocdecode_test_MAsn1Element_IndefExplicitIndefUpdateSample();
int mocdecode_test_MAsn1Element_ExplicitIndefUpdateSample();
int mocdecode_test_MAsn1Element_ExplicitUpdateSample();
int mocdecode_test_MAsn1Element_ExplicitIndefEncodingSample();
int mocdecode_test_MAsn1Element_indefiniteChunkedExplicit();
int mocdecode_test_MAsn1Element_SetOfExplicit();
int mocdecode_test_MAsn1Element_indefiniteSetOfExplicit();
int mocdecode_test_MAsn1Element_definiteSetOfExplicit();
int mocdecode_test_MAsn1Element_CMSEnvelopeSample();
int mocdecode_test_MAsn1Element_CMSEnvelopeChunkOctetSample();
int mocdecode_test_MAsn1Element_indefiniteChunkedSetOfExplicit();
int mocdecode_test_MAsn1Element_ConstructedTag();
int mocdecode_test_MAsn1Element_DataTag();
int mocdecode_test_MAsn1Element_indefOctet();
int mocdecode_test_MAsn1Element_indefOctetChunked();
int mocdecode_test_Signature();
int mocdecode_test_NestedDecoding();
int mocdecode_test_ChunkedDecoding();
int mocdecode_test_CA_ChunkedDecoding();



/* functions in file mocencode_test.c */
int mocencode_test_MAsn1Element_simpleInteger();
int mocencode_test_MAsn1Element_simpleIntegerAlloc();
int mocencode_test_MAsn1Element_updateInteger();
int mocencode_test_MAsn1Element_updateIntegerIndef();
int mocencode_test_MAsn1Element_simpleOID();
int mocencode_test_MAsn1Element_updateSingleEncodedIndef();
int mocencode_test_MAsn1Element_updateSingleEncodedForcedIndef();
int mocencode_test_MAsn1Element_updateMultipleEncodedIndef();
int mocencode_test_MAsn1Element_updateEncodedSampleTest();
int mocencode_test_MAsn1Element_updateEncoded();
int mocencode_test_MAsn1Element_updateEncodedExplicit();
int mocencode_test_MAsn1Element_updateEncodedIndefExplicit();
int mocencode_test_MAsn1Element_updateEncodedExplicitWithOptional();
int mocencode_test_MAsn1Element_encodedSETOFMultiple();
int mocencode_test_MAsn1Element_updateEncodedIndefOption0();
int mocencode_test_MAsn1Element_updateEncodedIndefOption1();



/* functions in file parseasn1_test.c */
int parseasn1_test_resume();
int parseasn1_test_bit_by_bit();
int parseasn1_test_simple();
int parseasn1_test_getdata();
int parseasn1_test_getnth_child();



/* functions in file parsecert_test.c */
int parsecert_test_extractDistinguishedName();
int parsecert_test_extractDates();
int parsecert_test_enumCRL();
int parsecert_test_enumAltName();
int parsecert_test_matchCommonName();
int parsecert_test_rsaSignAlgoExtraction();
int parsecert_test_verifyTimes();
int parsecert_test_verifyCerts();
int parsecert_test_stream();
int parsecert_test_rootCerts();
int parsecert_test_altSubjectNames();
int parsecert_test_keyUsageCerts();
int parsecert_test_keyUsageValueCerts();
int parsecert_test_CSR();
int parsecert_test_san_ipv4();
int parsecert_test_san_ipv6();

TestDescriptor gTestDescs[] = {

	TEST_DESC("derencoder_test.c", derencoder_test_time),

	TEST_DESC("derencoder_test.c", derencoder_test_opaque_test1),

	TEST_DESC("derencoder_test.c", derencoder_test_GetIntegerEncodingOffset),

	TEST_DESC("derencoder_test.c", derencoder_test_BER1),

	TEST_DESC("derencoder_test.c", derencoder_test_BER2),

	TEST_DESC("derencoder_test.c", derencoder_test_BER3),

	TEST_DESC("derencoder_test.c", derencoder_test_AddIntegerCopyData),

	TEST_DESC("derencoder_test.c", derencoder_test_BER4),

	TEST_DESC("derencoder_test.c", derencoder_test_BER5),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_simpleInteger),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteInteger),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteDefiniteInput),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_simpleOID),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteOIDString),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_simpleIA5),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_Sequence),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_Set),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_SetOf),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_IndefiniteSetOf),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_IndefiniteOctetOf),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_IndefiniteOctetOfChunked),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_Explicit),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitUpdate),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitIndefUpdate),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteExplicit),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_IndefExplicitIndefUpdateSample),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitIndefUpdateSample),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitUpdateSample),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitIndefEncodingSample),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteChunkedExplicit),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_SetOfExplicit),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteSetOfExplicit),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_definiteSetOfExplicit),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_CMSEnvelopeSample),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_CMSEnvelopeChunkOctetSample),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteChunkedSetOfExplicit),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_ConstructedTag),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_DataTag),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefOctet),

	TEST_DESC("mocdecode_test.c", mocdecode_test_MAsn1Element_indefOctetChunked),

	TEST_DESC("mocdecode_test.c", mocdecode_test_Signature),

	TEST_DESC("mocdecode_test.c", mocdecode_test_NestedDecoding),

	TEST_DESC("mocdecode_test.c", mocdecode_test_ChunkedDecoding),

	TEST_DESC("mocdecode_test.c", mocdecode_test_CA_ChunkedDecoding),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_simpleInteger),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_simpleIntegerAlloc),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateInteger),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateIntegerIndef),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_simpleOID),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateSingleEncodedIndef),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateSingleEncodedForcedIndef),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateMultipleEncodedIndef),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedSampleTest),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateEncoded),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedExplicit),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedIndefExplicit),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedExplicitWithOptional),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_encodedSETOFMultiple),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedIndefOption0),

	TEST_DESC("mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedIndefOption1),

	TEST_DESC("parseasn1_test.c", parseasn1_test_resume),

	TEST_DESC("parseasn1_test.c", parseasn1_test_bit_by_bit),

	TEST_DESC("parseasn1_test.c", parseasn1_test_simple),

	TEST_DESC("parseasn1_test.c", parseasn1_test_getdata),

	TEST_DESC("parseasn1_test.c", parseasn1_test_getnth_child),

	TEST_DESC("parsecert_test.c", parsecert_test_extractDistinguishedName),

	TEST_DESC("parsecert_test.c", parsecert_test_extractDates),

	TEST_DESC("parsecert_test.c", parsecert_test_enumCRL),

	TEST_DESC("parsecert_test.c", parsecert_test_enumAltName),

	TEST_DESC("parsecert_test.c", parsecert_test_matchCommonName),

	TEST_DESC("parsecert_test.c", parsecert_test_rsaSignAlgoExtraction),

	TEST_DESC("parsecert_test.c", parsecert_test_verifyTimes),

	TEST_DESC("parsecert_test.c", parsecert_test_verifyCerts),

	TEST_DESC("parsecert_test.c", parsecert_test_stream),

	TEST_DESC("parsecert_test.c", parsecert_test_rootCerts),

	TEST_DESC("parsecert_test.c", parsecert_test_altSubjectNames),

	TEST_DESC("parsecert_test.c", parsecert_test_keyUsageCerts),

	TEST_DESC("parsecert_test.c", parsecert_test_keyUsageValueCerts),

	TEST_DESC("parsecert_test.c", parsecert_test_CSR),

	TEST_DESC("parsecert_test.c", parsecert_test_san_ipv4),

	TEST_DESC("parsecert_test.c", parsecert_test_san_ipv6),
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

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_time, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_opaque_test1, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_GetIntegerEncodingOffset, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_BER1, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_BER2, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_BER3, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_AddIntegerCopyData, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_BER4, &pass);

	retVal += RUN_TEST_H( connfd, "derencoder_test.c", derencoder_test_BER5, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_simpleInteger, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteInteger, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteDefiniteInput, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_simpleOID, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteOIDString, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_simpleIA5, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_Sequence, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_Set, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_SetOf, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_IndefiniteSetOf, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_IndefiniteOctetOf, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_IndefiniteOctetOfChunked, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_Explicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitUpdate, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitIndefUpdate, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_IndefExplicitIndefUpdateSample, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitIndefUpdateSample, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitUpdateSample, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_ExplicitIndefEncodingSample, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteChunkedExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_SetOfExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteSetOfExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_definiteSetOfExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_CMSEnvelopeSample, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_CMSEnvelopeChunkOctetSample, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefiniteChunkedSetOfExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_ConstructedTag, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_DataTag, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefOctet, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_MAsn1Element_indefOctetChunked, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_Signature, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_NestedDecoding, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_ChunkedDecoding, &pass);

	retVal += RUN_TEST_H( connfd, "mocdecode_test.c", mocdecode_test_CA_ChunkedDecoding, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_simpleInteger, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_simpleIntegerAlloc, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateInteger, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateIntegerIndef, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_simpleOID, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateSingleEncodedIndef, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateSingleEncodedForcedIndef, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateMultipleEncodedIndef, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedSampleTest, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateEncoded, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedIndefExplicit, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedExplicitWithOptional, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_encodedSETOFMultiple, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedIndefOption0, &pass);

	retVal += RUN_TEST_H( connfd, "mocencode_test.c", mocencode_test_MAsn1Element_updateEncodedIndefOption1, &pass);

	retVal += RUN_TEST_H( connfd, "parseasn1_test.c", parseasn1_test_resume, &pass);

	retVal += RUN_TEST_H( connfd, "parseasn1_test.c", parseasn1_test_bit_by_bit, &pass);

	retVal += RUN_TEST_H( connfd, "parseasn1_test.c", parseasn1_test_simple, &pass);

	retVal += RUN_TEST_H( connfd, "parseasn1_test.c", parseasn1_test_getdata, &pass);

	retVal += RUN_TEST_H( connfd, "parseasn1_test.c", parseasn1_test_getnth_child, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_extractDistinguishedName, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_extractDates, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_enumCRL, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_enumAltName, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_matchCommonName, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_rsaSignAlgoExtraction, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_verifyTimes, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_verifyCerts, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_stream, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_rootCerts, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_altSubjectNames, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_keyUsageCerts, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_keyUsageValueCerts, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_CSR, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_san_ipv4, &pass);

	retVal += RUN_TEST_H( connfd, "parsecert_test.c", parsecert_test_san_ipv6, &pass);
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

