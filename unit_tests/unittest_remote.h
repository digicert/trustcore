/*
 *  unittest_remote.h
 *
 *   unit test remote execution support
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

#ifndef __UNITTEST_REMOTE_HEADER__
#define __UNITTEST_REMOTE_HEADER__

#ifdef __UNITTEST_REMOTE_SUPPORT__

#define UT_MAX_CMD_STR_SZ 40  /* Big enough for cmd with response postfix */
#define UT_DEFINE_CMD_DICTIONARY

/*
 CMD & RESP TIMEOUTS
 CMD_RECEIPT should be a *really* long time... maybe a half hour?
*/
#define CMD_RECEIPT_TIMEOUT_TGT      (60*60*1000)

/* CMD_RESPONSE should be a *reasonably* long time, Longer than any single test can take: Maybe a half hour? */
#define CMD_RESPONSE_TIMEOUT_HOST    (30*60*1000)

/* CMD_RESP_INCREMENTAL should be a short time, since we've already read a header, the rest should already be there... */
#define CMD_RESP_INCREMENTAL_TIMEOUT  (1*5*1000)

typedef struct {
    int   Index;
    char  Word[UT_MAX_CMD_STR_SZ];
} UT_DICT_ENTRY;

typedef enum
{
	UT_CMD_NONE,
    UT_CMD_STARTUP,
    UT_CMD_RUNTEST,
    UT_CMD_SHUTDOWN,
    UT_IND_OUTPUT,
    UT_NUM_CMD_TYPES
} ut_proto_cmd_t;

#ifdef UT_DEFINE_CMD_DICTIONARY
static UT_DICT_ENTRY ut_cmd_dict[UT_NUM_CMD_TYPES] =
{
	{ UT_CMD_NONE,     "NONE"},
	{ UT_CMD_STARTUP,  "STARTUP"},
	{ UT_CMD_RUNTEST,  "RUNTEST"},
	{ UT_CMD_SHUTDOWN, "SHUTDOWN"},
	{ UT_IND_OUTPUT,   "OUTPUT"},
};
#endif

typedef enum
{
	UT_RESP_NONE,
    UT_RESP_OK,
    UT_RESP_FINISHED,
    UT_RESP_FAILED,
    UT_RESP_PROTOCOL_ERROR,
    UT_NUM_RESP_TYPES
} ut_proto_resp_t;

#ifdef UT_DEFINE_CMD_DICTIONARY
static UT_DICT_ENTRY ut_resp_dict[UT_NUM_RESP_TYPES] =
{
	{ UT_RESP_NONE,     "NONE"},
	{ UT_RESP_OK,       "OK"},
	{ UT_RESP_FINISHED, "FINISHED"},
	{ UT_RESP_FAILED,   "FAILED"},
	{ UT_RESP_PROTOCOL_ERROR, "PROTOCOL_ERROR"},
};
#endif

#define UT_PKT_MO_HEAD_STR "MOHEAD>"  /* Must be <= 7 chars */
#define UT_PKT_MO_TAIL_STR "<MOTAIL"  /* Must be <= 7 chars */

#define UT_PKT_TEST_PASS_STR "PASS"  /* Must be <= 7 chars */
#define UT_PKT_TEST_FAIL_STR "FAIL"  /* Must be <= 7 chars */

#define UT_SMALL_CMD_BUFFSIZE  (256)   /* Way plenty big enough. */
#define UT_PKT_MAX_BUFFLEN (16*1024) /* This should be way more than enough. Should prob knock it down. */

#define UT_PKT_REBOOT_STR "REBOOT"   /* Can be any length. */
#define UT_PKT_REBOOT_OK_STR  "OK"   /* Can be any length. */

/* wire */
typedef struct CmdPacketHeader
{
    char header[8];
    char len[8];
    char pad1[4];
} CmdPacketHeader;

/* typedefs */
typedef struct CmdPacketTail
{
    char tail[8];
} CmdPacketTail;

/* typedefs */
typedef struct CmdPacketData
{
	ut_proto_cmd_t  cmdID;
	char *argbuff;     /* Ptr to just after NULL terminated CMD name. */
	int  argbufflen;   /* len of the rest of the buffer */
} CmdPacketData;

/* CMD return code values.*/
#define UT_ICMD_SUCCESS  0
#define UT_ICMD_FAILED  -1

#define UT_LOCAL_HOST_NAME "localhost"
#define UT_LOCAL_HOST_IP "127.0.0.1"
#define UT_TGT_PORTID 42042          /* Change this to allow running two diff tests on same host.*/
#define UT_TGT_REBOOT_PORTID 42044   /* Change this to allow running two diff tests on same host.*/

/* prototypes */
/* Common to Host and Target */
int ut_getcmdindex(char *str);
char *ut_getcmdstr(int index);

int ut_testindexfromstr(const TestDescriptor* pTestDict, int nEntries, char* str);

int ut_getrespindex(char *str);
char *ut_getrespstr(int index);

CmdPacketData *ut_alloc_pktdata(int maxbufflen); /* allocates the buffer and the wrapping struct.*/
void ut_free_pktdata(CmdPacketData *pkt); /* frees both wrapping struct and char buffer inside.*/

int ut_writecmd_to_socket(int connfd, CmdPacketData *pkt); /* Encodes and writes cmd to socket.*/
int ut_writeresponse_to_socket(int connfd, CmdPacketData *pkt, ut_proto_resp_t respId); /* Encodes and writes cmd response to socket. */

int ut_getcmd_from_socket(int connfd, CmdPacketData **ppCmdData); /* blocks waiting for complete cmd, caller must free pPktData */
int ut_getcmdresp2onse_from_socket(int connfd, ut_proto_resp_t *pRespID, CmdPacketData **ppCmdData); /* blocks waiting for complete cmd response, caller must free pPktData */

/*
 Host side
*/

int ut_load_test_target_h(const char *tgtname, const char *execname,
                          int argc, char* argv[], int timeoutsecs);  /* May exec on localhost, may be a nop. */

int ut_connect_test_target_h(const char *tgtname, const char *execname,
						     int argc, char* argv[], int timeoutsecs, int *pconnfd); /* Connect via socket. */

int ut_disconnect_test_target_h(int *pconnfd); /* Closes the socket. */

int ut_startup_cmd_h(int connfd); /* Send Startup CMD and wait for ACK. */

int ut_shutdown_cmd_h(int connfd, int timeoutsecs); /* Send Shutdown cmd and wait for ACK. */

int ut_runtest_cmd_h( int connfd, const char* testFunName, const char* fileName, int *pRetval); /* Send RUNTEST cmd, and wait until _FINISHED received. */

int ut_process_output_ind_h( CmdPacketData *pPktData); /* Process incoming Log output. Typically during RUNTEST cmd processing. */

/**************************************
 Target side
***************************************/
int ut_initcomm_tgt( struct sockaddr *phostip, int *pconnfd);  /* Listen for incoming connections, and accept, returning connected socket. */

int ut_write_output_cmd_tgt(int connfd, const char *msg);

int ut_waitfor_startup_cmd_tgt(int connfd);

int ut_waitfor_runtest_cmd_tgt(int connfd, TestDescriptor* tests, int num_tests);

int ut_stopcomm_tgt( int *pconnfd, int statusin);

/* macros */


#endif /* __UNITTEST_REMOTE_SUPPORT__ */

#endif /* __UNITTEST_REMOTE_HEADER__ */









