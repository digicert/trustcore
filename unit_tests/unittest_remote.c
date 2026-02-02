/*
 *  unittest_remote.c
 *
 *   unit test remote support
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

#include "../src/common/moptions.h"
#include "../src/common/mtypes.h"
#include "../src/common/mocana.h"


#include "../src/common/mdefs.h"
#include "../src/common/merrors.h"
#include "../src/common/mstdlib.h"
#include "../src/common/mrtos.h"
#include "../src/common/mtcp.h"

#include "unittest.h"


#define UT_DEFINE_DICTIONARY
#include "unittest_remote.h"

#if (defined(WIN32) && defined(_DEBUG))
#include <CrtDbg.h>
#endif

#include <assert.h>
#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined( __RTOS_SOLARIS__) || \
    defined(__RTOS_VXWORKS__) || defined( __RTOS_OSX__) || \
    defined(__RTOS_OPENBSD__) || defined( __RTOS_FREEBSD__) || \
    defined(__RTOS_IRIX__) || defined( __RTOS_DUMMY__ ) || \
    defined(__RTOS_SYMBIAN32__)  || defined(__RTOS_WINCE__) 
#include <stdio.h>
#include <string.h>
#define PRINTF      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#endif

#if defined(__RTOS_LINUX__) || defined(__RTOS_OPENBSD__) || \
    defined(__RTOS_OPENBSD__) || defined( __RTOS_SOLARIS__)
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
#elif defined(__RTOS_VXWORKS__)
  #include <vxWorks.h>
  #include <sockLib.h>
  #include <inetLib.h>
  #include <netdb.h>
#endif

/*-------------------------------------------------------------------------*/
#define UT_DBG_COMM_V      1  /* Verbose // 0 = OFF 1 = ON */
#define UT_DBG_COMM_ERR    1  /* Errors                    */
#define UT_DBG_CMD_RESP    1  /* 0 = OFF 1 = ON            */
#define UT_DBG_COMM_REBOOT 1  /* Reboot cmd stuff // 0 = OFF 1 = ON */

#define UT_DBG_HOST_OUT   1  /* Print (or not) if we are on the host side */
#define UT_DBG_TARGET_OUT 1  /* Print (or not) if we are on the host side */
#define UT_DEBUG_PRINT(t,b,c) ut_debug_print(__FILE__, __LINE__, t, b, c)


/*-------------------------------------------------------------------------*/
#ifdef __UNITTEST_REMOTE_SUPPORT__

/*------------------------------------------------------------------*/

/**************************************
 Internal functions
*/
static int ut_idfromstr(const UT_DICT_ENTRY* pDict, int nEntries, char* str);   /* totally generic */
static char *ut_strfromid(const UT_DICT_ENTRY* pDict, int nEntries, int index); /* totally generic */

/**************************************
 Dead target shortcuts.
*/
static char tgt_alive_flag;
static char tgt_is_alive(void);
static void set_tgt_is_alive(char fff);
static int tgt_read_failure(int rc, int timeout, int bytesread, int expectlen);


static MSTATUS tcp_read_avail(TCP_SOCKET socket, sbyte *pBuffer,
        ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout);

static MSTATUS tcp_read_avail(TCP_SOCKET socket, sbyte *pBuffer,
        ubyte4 maxBytesToRead, ubyte4 *pNumBytesRead, ubyte4 msTimeout)
{
	return TCP_READ_ALL(socket, pBuffer, maxBytesToRead, pNumBytesRead, msTimeout);
}


#define MAX_TEST_NAME_LEN 128

static void ut_debug_print(const char* pfile, int iline, int printthis, char *str1, char *str2);

static void ut_debug_print(const char* pfile, int iline, int printthis, char *str1, char *str2)
{
	char *pNull = "null";
	if (printthis == 0)
			return;
	if (str1 == NULL) str1 = pNull;
	if (str2 == NULL) str2 = pNull;
#if (defined(__UNITTEST_REMOTE_RUNHOST__) && UT_DBG_HOST_OUT)
	printf("%s : %d : %s%s\n",pfile,iline,str1,str2);
#endif
#if (defined(__UNITTEST_REMOTE_RUNTARGET__) && UT_DBG_TARGET_OUT)
	printf("%s : %d : %s%s\n",pfile,iline,str1,str2);
#endif


}

/*****************************************
 Dead target shortcuts.
*/
static char tgt_is_alive(void)
{
	return tgt_alive_flag;
}

static void set_tgt_is_alive(char fff)
{
	tgt_alive_flag = fff;
}

static int tgt_read_failure(int rc, int timeout, int bytesread, int expectlen)
{
	static char dbgbuff[80] = { 0 };
	set_tgt_is_alive(FALSE);
	sprintf(dbgbuff," rc = %d timeout = %d bytesread = %d, expectlen = %d",rc,timeout,bytesread,expectlen);
	UT_DEBUG_PRINT(UT_DBG_COMM_ERR,"COMM ERROR: TCP_READ_AVL returned ",dbgbuff);
	return ERR_TCP_READ_ERROR;
}


/******************************************
 Cmd Enum <--> String conversion
*/
static int ut_idfromstr(const UT_DICT_ENTRY* pDict, int nEntries, char* str)
{
    int i;
    sbyte4 x;

    int index = 0; /* 0 == NONE. (invalid) */

    char testword[UT_MAX_CMD_STR_SZ]="";

    for (i=0; i < nEntries; i++)
    {
    	DIGI_STRCBCPY((sbyte *)testword,(ubyte4)UT_MAX_CMD_STR_SZ,(sbyte *)(pDict + i)->Word);
        if (DIGI_STRLEN((sbyte *)testword) == DIGI_STRLEN((sbyte *)str))
        {
            x = DIGI_STRCMP((sbyte *)testword,(sbyte *)str);

            if (x == 0)
            {
                index = (pDict + i)->Index;
                break;
            }
        }
    }
    return index;

}

static char *ut_strfromid(const UT_DICT_ENTRY* pDict, int nEntries, int index)
{
	int id;
	if (index < nEntries)
	{

		id = (pDict + index)->Index;
		return ((id == index) ? (char *)(pDict + index)->Word : NULL); /* Make sure table is well-ordered.*/
	}

	return NULL;
}

int ut_getcmdindex(char *str)
{
	return ut_idfromstr(ut_cmd_dict, UT_NUM_CMD_TYPES, str);
}

char *ut_getcmdstr(int index)
{
	return ut_strfromid(ut_cmd_dict, UT_NUM_CMD_TYPES, index);
}


int ut_getrespindex(char *str)
{
	return ut_idfromstr(ut_resp_dict, UT_NUM_RESP_TYPES, str);
}

char *ut_getrespstr(int index)
{
	return ut_strfromid(ut_resp_dict, UT_NUM_RESP_TYPES, index);
}

/************************************************
 Test String to Func Ptr conversion
*/
int ut_testindexfromstr(const TestDescriptor* pTestDict, int nEntries, char* str)
{
    int i;
    sbyte4 x;

    int index = -1; /* -1 == NONE. (invalid) */
    char testword[MAX_TEST_NAME_LEN]="";

    for (i=0; i < nEntries; i++)
    {
    	DIGI_STRCBCPY((sbyte *)testword,sizeof(testword),(sbyte *)(pTestDict + i)->testName);
        if (DIGI_STRLEN((sbyte *)testword) == DIGI_STRLEN((sbyte *)str))
        {
            x = DIGI_STRCMP((sbyte *)testword,(sbyte *)str);

            if (x == 0)
            {
                index = i;
                break;
            }
        }
    }
    return index;

}

/********************************************
 Pkt memory management
*/
/* allocates the buffer and the wrapping struct. */
CmdPacketData *ut_alloc_pktdata(int maxbufflen)
{
	CmdPacketData *pkt = NULL;
	/* Get the wrapper */
	if (NULL == (pkt = MALLOC(sizeof(CmdPacketData))))
	{
		return NULL;
	}

	/* Get the buffer space */
	if (NULL == (pkt->argbuff = MALLOC(maxbufflen)))
	{
		FREE(pkt);
		return NULL;
	}

	pkt->argbufflen = maxbufflen;
	pkt->cmdID = UT_CMD_NONE;

	return pkt;

}

/* frees both wrapping struct and char buffer inside. */
void ut_free_pktdata(CmdPacketData *pkt)
{
	if (pkt == NULL)
		return;

	if (pkt->argbuff)
		FREE(pkt->argbuff);

	FREE(pkt);

}

/******************************************************
 Pkt Marshal/DeMarshal and Socket write/read.
*/
/* Encodes and writes cmd to socket. */
int ut_writecmd_to_socket(int connfd, CmdPacketData *pkt)
{
	MSTATUS myrc = OK;
	int cmdlen = 0;
	int len = 0;
	unsigned int numwritten = 0;

	char cmdbuf[UT_MAX_CMD_STR_SZ] = { 0 };
	char *cmdptr = NULL;

	CmdPacketHeader head = { {0} };
	CmdPacketTail tail = { {0} };

	/* Set up Header and Tail, and Cmd buff. */
	DIGI_STRCBCPY((sbyte *)head.header,(ubyte4)sizeof(head.header),(sbyte *)UT_PKT_MO_HEAD_STR);
	if (NULL != (cmdptr = ut_getcmdstr(pkt->cmdID)))
		DIGI_STRCBCPY((sbyte *)cmdbuf, UT_MAX_CMD_STR_SZ, (sbyte *)cmdptr);
	else
		myrc = ERR_GENERAL;

	cmdlen = DIGI_STRLEN((sbyte *)cmdbuf);
	cmdlen++; /* For NULL after the cmd. */
	len = cmdlen;
	len += pkt->argbufflen;
	len++; /* For NULL after the cmd args. */

	DIGI_LTOA(len, (sbyte *)head.len, sizeof(head.len));

	DIGI_STRCBCPY((sbyte *)tail.tail,(ubyte4)sizeof(tail.tail),(sbyte *)UT_PKT_MO_TAIL_STR);

	/* Write out Header, CMD, Args, and Tail. */
	if (myrc == OK)
	{
		myrc = TCP_WRITE_ALL(connfd,(sbyte *)&head, sizeof(head), &numwritten);
	}

	if (myrc == OK)
	{
		myrc = TCP_WRITE_ALL(connfd,(sbyte *)cmdbuf, cmdlen, &numwritten);
	}

	if (myrc == OK)
	{
		myrc = TCP_WRITE_ALL(connfd,(sbyte *)pkt->argbuff, pkt->argbufflen+1, &numwritten);
	}

	if (myrc == OK)
	{
		printf("ut_writecmd_to_socket: &tail= %x, sizeof(tail)= %d, &numwritten= %x\n", &tail, sizeof(tail), &numwritten);

		myrc = TCP_WRITE_ALL(connfd,(sbyte *)&tail, sizeof(tail), &numwritten);
	}

	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Header.header=",head.header);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Header.len=",head.len);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Pkt->cmdbuff=",cmdbuf);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Pkt->argbuff=",pkt->argbuff);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Tail.tail=",tail.tail);

	return myrc;
}

/* Encodes and writes cmd resp to socket.*/
int ut_writeresponse_to_socket(int connfd, CmdPacketData *pkt, ut_proto_resp_t respId)
{
	MSTATUS myrc = OK;
	int cmdlen = 0;
	int len = 0;
	unsigned int numwritten = 0;

	char cmdbuf[UT_MAX_CMD_STR_SZ] = { 0 };
	char *cmdptr = NULL;

	CmdPacketHeader head = { {0} };
	CmdPacketTail tail = { {0} };

	/* Set up Header and Tail, and Cmd buff. */
	DIGI_STRCBCPY((sbyte *)head.header,(ubyte4)sizeof(head.header),(sbyte *)UT_PKT_MO_HEAD_STR);

	/* Get CMD string. */
	if (NULL != (cmdptr = ut_getcmdstr(pkt->cmdID)))
		DIGI_STRCBCPY((sbyte *)cmdbuf, UT_MAX_CMD_STR_SZ, (sbyte *)cmdptr);
	else
		myrc = ERR_GENERAL;

	cmdlen = DIGI_STRLEN((sbyte *)cmdbuf);

	/* Put an underscore between the CMD and the RESPONSE string. */
	cmdbuf[cmdlen] = '_';
	cmdlen++;

	/* Append RESP string. */
	if (NULL != ut_getrespstr(respId))
		DIGI_STRCBCPY((sbyte *)&cmdbuf[cmdlen], UT_MAX_CMD_STR_SZ-cmdlen, (sbyte *)ut_getrespstr(respId));
	else
		myrc = ERR_GENERAL;

    cmdlen = DIGI_STRLEN((sbyte *)cmdbuf);  /* Now it's the length of cmd_resp */
	cmdlen++; /* For NULL after the cmd_resp */
	len = cmdlen;
	len += pkt->argbufflen;
	len++; /* For NULL after the cmd args. */

	DIGI_LTOA(len, (sbyte *)head.len, sizeof(head.len));

	DIGI_STRCBCPY((sbyte *)tail.tail,(ubyte4)sizeof(tail.tail),(sbyte *)UT_PKT_MO_TAIL_STR);

	/* Write out Header, CMD, Args, and Tail. */
	if (myrc == OK)
		myrc = TCP_WRITE_ALL(connfd,(sbyte *)&head, sizeof(head), &numwritten);

	if (myrc == OK)
		myrc = TCP_WRITE_ALL(connfd,(sbyte *)cmdbuf, cmdlen, &numwritten);

	if (myrc == OK)
		myrc = TCP_WRITE_ALL(connfd,(sbyte *)pkt->argbuff, pkt->argbufflen+1, &numwritten);

	if (myrc == OK)
		myrc = TCP_WRITE_ALL(connfd,(sbyte *)&tail, sizeof(tail), &numwritten);

	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Header.header=",head.header);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Header.len=",head.len);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Pkt->cmdbuff=",cmdbuf);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Pkt->argbuff=",pkt->argbuff);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Send:: Tail.tail=",tail.tail);

	return myrc;
}

/* blocks waiting for complete cmd, caller must free pPktData */
int ut_getcmd_from_socket(int connfd, CmdPacketData **ppCmdData)
{
	MSTATUS myrc = OK;
	int cmdlen = 0;
	int len = 0;
	int cmpresult = 0;
	unsigned int bytesread = 0;

	static char dbgbuff[80] = { 0 };

	CmdPacketData *pGuts = NULL;

	CmdPacketHeader head = { {0} };
	CmdPacketTail tail = { {0} };

	/* Read and process the header. */
	myrc = tcp_read_avail(connfd,(sbyte *)&head, sizeof(head), &bytesread, CMD_RECEIPT_TIMEOUT_TGT);
	if (bytesread != sizeof(head))
	{
		myrc = tgt_read_failure(myrc, CMD_RECEIPT_TIMEOUT_TGT, bytesread, sizeof(head));
	}
	else
		head.pad1[0] = '\0'; /* Safety first. No unbounded string possible now. */

    /* This is safe since it starts out as a struct w/ NULLs (above). */
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Header.header=",head.header);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Header.len=",head.len);

	if (myrc == OK)
	{
		cmpresult = DIGI_MEMCMP((ubyte *)head.header, (ubyte *)UT_PKT_MO_HEAD_STR, sizeof(head.header), &cmpresult);
		if ((myrc != OK) || (cmpresult != 0))
		{
			UT_DEBUG_PRINT(UT_DBG_COMM_ERR,"BogusHeader=",head.header);
			myrc = ERR_INVALID_ARG;
		}
		else
		{
			len = DIGI_ATOL((const sbyte*)head.len, NULL);
			if ((len <= 0) || (len > UT_PKT_MAX_BUFFLEN))
			{
				UT_DEBUG_PRINT(UT_DBG_COMM_ERR,"BogusLen=",head.len);
				myrc = ERR_INVALID_ARG;

			}
			else if (NULL == (pGuts = ut_alloc_pktdata(len)))
			{
				myrc = ERR_MEM_ALLOC_FAIL;
			}
		}
	}


	/* Read the guts.*/
	if (myrc == OK)
	{
		myrc = tcp_read_avail(connfd,(sbyte *)pGuts->argbuff, len, &bytesread, CMD_RESP_INCREMENTAL_TIMEOUT);
		if (bytesread != len)
    	{
			myrc = tgt_read_failure(myrc, CMD_RESP_INCREMENTAL_TIMEOUT, bytesread, len);
    	}
		else
			UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Pkt->cmdbuff=",pGuts->argbuff);
	}


	/* Read the tail.*/
	if (myrc == OK)
	{
		myrc = tcp_read_avail(connfd,(sbyte *)&tail, sizeof(tail), &bytesread, CMD_RESP_INCREMENTAL_TIMEOUT);
		if (bytesread != sizeof(tail))
    	{
			myrc = tgt_read_failure(myrc, CMD_RESP_INCREMENTAL_TIMEOUT, bytesread, sizeof(tail));
    	}
	}

	/* Validate the tail.*/
	if (myrc == OK)
	{
		cmpresult = DIGI_MEMCMP((ubyte *)tail.tail, (ubyte *)UT_PKT_MO_TAIL_STR, sizeof(tail.tail), &cmpresult);
		if ((myrc != OK) || (cmpresult != 0))
		{
			UT_DEBUG_PRINT(UT_DBG_COMM_ERR,"BogusTail=",tail.tail);
			myrc = ERR_INVALID_ARG;
		}
	}

	/* Process the guts.*/
	if (myrc == OK)
	{
		/* Figure out which cmd.*/
		pGuts->cmdID = ut_getcmdindex(pGuts->argbuff);

		/* Move the Cmd to the left.*/
		cmdlen = DIGI_STRLEN((const sbyte *)pGuts->argbuff);
		len = len - (cmdlen+1); /* cmd NULL CHAR too.*/
		len--; /* Drop the argbuff NULL CHAR too.*/
		if (len > 0)
		{
			DIGI_MEMCPY(pGuts->argbuff, pGuts->argbuff+cmdlen+1, len);
		}
		pGuts->argbufflen = len;
		pGuts->argbuff[len] = '\0';  /* Null terminate it.*/

		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Pkt->argbuff=",pGuts->argbuff);
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Tail.tail=",tail.tail);

	}

	if (myrc == OK)
	{
		*ppCmdData = pGuts; /* Return it to the caller. He'll release it.*/
	}
	else
	{
		if (pGuts != NULL)
		{
			ut_free_pktdata(pGuts);
			*ppCmdData = NULL;
		}

	}
	return myrc;
}

static char *findfirst_underscore(char *pStr, int strlen)
{
	int ndx = 0;
	if ((pStr == NULL)||(strlen <=0))
	{
		return NULL;
	}

	while ((*pStr != '\0') && (ndx < strlen))
	{
		if (*pStr == '_')
			return pStr;
		else
			pStr++;
	}
	return NULL;
}

/* blocks waiting for complete cmd response, caller must free pPktData*/
int ut_getcmdresponse_from_socket(int connfd, ut_proto_resp_t *pRespID, CmdPacketData **ppCmdData)
{
	MSTATUS myrc = OK;
	int cmdlen = 0;
	int len = 0;
	int cmpresult = 0;
	unsigned int bytesread = 0;

	static char dbgbuff[80] = { 0 };

	char *pUnder = NULL;
	CmdPacketData *pGuts = NULL;

	CmdPacketHeader head = { {0} };
	CmdPacketTail tail = { {0} };

	/* Read and process the header.*/
	myrc = tcp_read_avail(connfd,(sbyte *)&head, sizeof(head), &bytesread, CMD_RESPONSE_TIMEOUT_HOST);
	if (bytesread != sizeof(head))
	{
		myrc = tgt_read_failure(myrc, CMD_RESPONSE_TIMEOUT_HOST, bytesread, sizeof(head));
	}

	if (myrc == OK)
	{
		myrc = DIGI_MEMCMP((ubyte *)head.header, (ubyte *)UT_PKT_MO_HEAD_STR, sizeof(head.header), &cmpresult);
		if ((myrc != OK) || (cmpresult != 0))
			myrc = ERR_INVALID_ARG;
		else
		{
			len = DIGI_ATOL((const sbyte*)head.len, NULL);
			if ((len <= 0) || (len > UT_PKT_MAX_BUFFLEN))
				myrc = ERR_INVALID_ARG;
			else if (NULL == (pGuts = ut_alloc_pktdata(len)))
				myrc = ERR_MEM_ALLOC_FAIL;
		}
	}

	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Header.header=",head.header);
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Header.len=",head.len);

	/* Read the guts.*/
	if (myrc == OK)
	{
		myrc = tcp_read_avail(connfd,(sbyte *)pGuts->argbuff, len, &bytesread, CMD_RESP_INCREMENTAL_TIMEOUT);
		if (bytesread != len)
    	{
			myrc = tgt_read_failure(myrc, CMD_RESP_INCREMENTAL_TIMEOUT, bytesread, len);
    	}
	}
	else
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Not reading Pkt internals.","Done. (1)");
	}

	/* Read the tail.*/
	if (myrc == OK)
	{

		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Pkt->cmdbuff=",pGuts->argbuff);

		myrc = tcp_read_avail(connfd,(sbyte *)&tail, sizeof(tail), &bytesread, CMD_RESP_INCREMENTAL_TIMEOUT);
		if (bytesread != sizeof(tail))
    	{
			myrc = tgt_read_failure(myrc, CMD_RESP_INCREMENTAL_TIMEOUT, bytesread, sizeof(tail));
    	}
	}
	else
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Not reading Pkt Tail.","Done. (2)");
	}

	/* Validate the tail.
	if (myrc == OK)
	{
		myrc = DIGI_MEMCMP((ubyte *)tail.tail, (ubyte *)UT_PKT_MO_TAIL_STR, sizeof(tail.tail), &cmpresult);
		if ((myrc != OK) || (cmpresult != 0))
			myrc = ERR_INVALID_ARG;
	}
    */

	/* Process the guts.*/
	if (myrc == OK)
	{
		/* Figure out which response (or INDICATION).*/
		pUnder = findfirst_underscore(pGuts->argbuff, len);
		if (pUnder)
			*pUnder = '\0'; /* Replace it w/ a NULL.*/
		pGuts->cmdID = ut_getcmdindex(pGuts->argbuff);

		/* Move the Cmd to the left.*/
		cmdlen = DIGI_STRLEN((const sbyte *)pGuts->argbuff);
		len = len - (cmdlen+1); /* cmd NULL CHAR too.*/
		len--; /* Drop the argbuff NULL CHAR too.*/

		if (len > 0)
		{
			DIGI_MEMCPY(pGuts->argbuff, pGuts->argbuff+cmdlen+1, len);
		}
		pGuts->argbufflen = len;
		pGuts->argbuff[len] = '\0';  /* Null terminate it.*/

		if (len > 0)
		{
			/* Get the Response.*/
			*pRespID = ut_getrespindex(pGuts->argbuff);

			/* Move the Cmd (RESP) to the left.*/
			cmdlen = DIGI_STRLEN((const sbyte *)pGuts->argbuff);
			len = len - (cmdlen+1);
			if (len > 0)
			{
				DIGI_MEMCPY(pGuts->argbuff, pGuts->argbuff+cmdlen+1, len);
			}
			pGuts->argbufflen = len;
			pGuts->argbuff[len] = '\0';  /* Null terminate it.*/
		}
	}


	if (myrc == OK)
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Pkt->argbuff=",pGuts->argbuff);
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Tail.tail=",tail.tail);
		*ppCmdData = pGuts; /* Return it to the caller. He'll release it.*/
	}
	else
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Recv:: Not OK"," Done. (3)");
		if (pGuts != NULL)
		{
			ut_free_pktdata(pGuts);
			*ppCmdData = NULL;
		}

	}

	return myrc;
}


/*
 Real remote support.
*/

/*/////////////////////////////////////*/
/* Host side */
/*////////////////////////////////////*/
#define MAX_IPADDR_SIZE 40
/*------------------------------------------------------------------*/
static int ut_getHostByName(char* tgtname, sbyte* pIpAddress)
{
	int status = OK;
    struct hostent *h = NULL;

    if ( NULL == ( h = gethostbyname(tgtname)))
    {
        status = ERR_TCP;
    }
    else
    {
    	DIGI_STRCBCPY(pIpAddress,MAX_IPADDR_SIZE,(sbyte *)inet_ntoa(*((struct in_addr *)h->h_addr)));
    }

    return status;
}
/*------------------------------------------------------------------*/

/* May exec on localhost, may be a nop.*/
int ut_load_test_target_h(const char *tgtname, const char *execname,
						     int argc, char* argv[], int timeoutsecs)
{
	int rc = OK;

    /*/KRB: Makes Sig-HUP not work....*/
    /*/KRB: TCP_INIT(); Need to do this somewhere.*/
	set_tgt_is_alive(FALSE);

	UT_DEBUG_PRINT(UT_DBG_COMM_V,"ut_load_test_target_h::"," done.");

	return rc;
}


/* Connect via socket.*/
int ut_connect_test_target_h(const char *tgtname, const char *execname,
						     int argc, char* argv[], int timeoutsecs, int *pconnfd)
{
	int myrc = OK;

    TCP_SOCKET      mySocket;
    sbyte           serverIpAddress[MAX_IPADDR_SIZE];  /* plenty big.*/
    const ubyte2    serverPort = UT_TGT_PORTID;
	char alldone = FALSE;
	int retries = ((timeoutsecs+1)*2);

	static char dbgbuff[512] = { 0 };

#if UT_DBG_COMM_V
	static char dbgarg[256] = { 0 };
	sprintf(dbgbuff,"(Tgt:%s)(Exec:%s)(Timeout:%d)(argc:%d)",tgtname,execname,timeoutsecs,argc);
	if (argc == 0)
	{
		sprintf(dbgarg,"(argv:%s)","<<none>>");
		strcat(dbgbuff,dbgarg);
	}
	else
	{
		int i;
		for (i = 0; i < argc; i++)
		{
			sprintf(dbgarg,"(argv[%d]:%s)",i,argv[i]);
			strcat(dbgbuff,dbgarg);
		}
	}
	UT_DEBUG_PRINT(UT_DBG_COMM_V,"Connect_test_tgt::",dbgbuff);
#endif

	/* KRB: NOTE: Currently ignoring the execname, argc & argv parms: Probably always will.*/

	if (0 == DIGI_STRCMP((const sbyte *)tgtname, (const sbyte *)UT_LOCAL_HOST_NAME))
	{
		/* Go w/ the default.*/
		DIGI_STRCBCPY(serverIpAddress,sizeof(serverIpAddress),(sbyte *)UT_LOCAL_HOST_IP);
	}
	else
	{
		myrc = ut_getHostByName((char *)tgtname, serverIpAddress);
	}

	if (myrc == OK)
	{
		while (alldone != TRUE)
		{
			UT_DEBUG_PRINT(UT_DBG_COMM_V,"Connect_test_tgt:: Connect()... ",(char *)serverIpAddress);
			myrc = TCP_CONNECT(&mySocket, serverIpAddress, serverPort);
		    if (myrc == 0)
		    {
		    	*pconnfd = mySocket;
		    	alldone = TRUE;

		    	set_tgt_is_alive(TRUE);

		    }
		    else if (myrc == ERR_TCP_CONNECT_ERROR)
		    {
		    	if (retries-- <= 0)
		    	{
					sprintf(dbgbuff," rc = %d",myrc);
					UT_DEBUG_PRINT(UT_DBG_COMM_ERR,"Connect_test_tgt: Connect() failed.", dbgbuff);
		    		alldone = TRUE; /* bail out and fail.*/
		    	}
		    	else
		    	{
			    	/* Let's assume the TARGET isn't Accepting connections yet, and keep retrying...*/
					UT_DEBUG_PRINT(UT_DBG_COMM_V,"Connect_test_tgt::","Connect() failed. sleeping...");
					RTOS_sleepMS((1000/2)); /* Try twice per sec.*/
		    	}
		    }
		    else
		    {
		    	/* Something else bad and unexpected.*/
				sprintf(dbgbuff," rc = %d",myrc);
				UT_DEBUG_PRINT(UT_DBG_COMM_ERR,"Connect_test_tgt: Connect() failed.", dbgbuff);
		    	alldone = TRUE;
		    }

        } /* end while notdone.*/
	}
	else
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"Could not get IP Address for target::",(char *)tgtname);
	}

	return myrc;

}

int ut_disconnect_test_target_h(int *pconnfd)
{
	int myrc;
	myrc = TCP_CLOSE_SOCKET(*pconnfd);
	*pconnfd = 0;
	return myrc;
}


/* Send Startup CMD and wait for ACK.*/
int ut_startup_cmd_h(int connfd)
{
	int myrc = OK;
	CmdPacketData *MyCmdpkt = NULL;
	ut_proto_resp_t MyRespID = UT_RESP_NONE;
	char alldone = FALSE;

	if (tgt_is_alive() == FALSE)
	{
		UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD:"," Target Comm failed. all done.");
		myrc = ERR_GENERAL;
		return myrc; /* No target, no continue.*/
	}

	if (NULL == (MyCmdpkt = ut_alloc_pktdata(UT_SMALL_CMD_BUFFSIZE)))
	{
		myrc = ERR_MEM_ALLOC_FAIL;
		return myrc; /* No memory, no continue.*/
	}
	MyCmdpkt->cmdID = UT_CMD_STARTUP;
	MyCmdpkt->argbufflen = 0;
	MyCmdpkt->argbuff[MyCmdpkt->argbufflen] = '\0';

	if (myrc == OK)
	{
		myrc = ut_writecmd_to_socket(connfd, MyCmdpkt);
		ut_free_pktdata(MyCmdpkt);
		MyCmdpkt = NULL;
	}

	if (myrc != OK)
	{
		UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD:"," Send failed. all done.");
		alldone = TRUE; /* Bail.*/
	}
	else
	{
		alldone = FALSE;
	}

	while (alldone != TRUE)
	{
		if (myrc == OK)
		{
			myrc = ut_getcmdresponse_from_socket(connfd, &MyRespID, &MyCmdpkt);
		}

		if ( (myrc == OK) && (MyCmdpkt != NULL))
		{
			if (MyCmdpkt->cmdID == UT_CMD_STARTUP)
			{
				/* Good. It's what we expected.*/
				if (MyRespID == UT_RESP_OK)
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD: GOOD:RESP=",ut_getrespstr(MyRespID));
				}
				else
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD: BAD:RESP=",ut_getrespstr(MyRespID));
				}
				alldone = TRUE;
			}
			else if (MyCmdpkt->cmdID == UT_IND_OUTPUT)
			{
				/* Moderately surprising. *Log output.*/
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD: OUTPUT CMD RECEIVED=",ut_getrespstr(MyRespID));
				myrc = ut_process_output_ind_h(MyCmdpkt);
			}
			else
			{
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD: BAD:Cmd=",ut_getcmdstr(MyCmdpkt->cmdID));
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD: BAD:RESP=",ut_getrespstr(MyRespID));
				alldone = TRUE;
				myrc = ERR_GENERAL;
			}
		}
		else
		{
			UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_CMD:"," Response failed. all done.");
			alldone = TRUE; /* Bail.*/
		}

		if (MyCmdpkt != NULL)
		{
			ut_free_pktdata(MyCmdpkt);
			MyCmdpkt = NULL;
		}

	} /* end while not alldone;*/

	return myrc;
}


/* Send Shutdown cmd and wait for ACK.*/
int ut_shutdown_cmd_h(int connfd, int timeoutsecs)
{
	int myrc = OK;
	CmdPacketData *MyCmdpkt = NULL;
	ut_proto_resp_t MyRespID = UT_RESP_NONE;
	char alldone = FALSE;

	if (tgt_is_alive() == FALSE)
	{
		UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD:"," Target Comm failed. all done.");
		myrc = ERR_GENERAL;
		return myrc; /* No target, no continue.*/
	}

	if (NULL == (MyCmdpkt = ut_alloc_pktdata(UT_SMALL_CMD_BUFFSIZE)))
	{
		myrc = ERR_MEM_ALLOC_FAIL;
		return myrc; /* No memory, no continue.*/
	}
	MyCmdpkt->cmdID = UT_CMD_SHUTDOWN;
	MyCmdpkt->argbufflen = 0;
	MyCmdpkt->argbuff[MyCmdpkt->argbufflen] = '\0';

	if (myrc == OK)
	{
		myrc = ut_writecmd_to_socket(connfd, MyCmdpkt);
		ut_free_pktdata(MyCmdpkt);
		MyCmdpkt = NULL;
	}

	if (myrc != OK)
	{
		UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD:"," Send failed. all done.");
		alldone = TRUE; /* Bail.*/
	}
	else
	{
		alldone = FALSE;
	}

	while (alldone != TRUE)
	{
		if (myrc == OK)
		{
			myrc = ut_getcmdresponse_from_socket(connfd, &MyRespID, &MyCmdpkt);
		}

		if ( (myrc == OK) && (MyCmdpkt != NULL))
		{
			if (MyCmdpkt->cmdID == UT_CMD_SHUTDOWN)
			{
				/* Good. It's what we expected.*/
				if (MyRespID == UT_RESP_OK)
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD: GOOD:RESP=",ut_getrespstr(MyRespID));
				}
				else
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD: BAD:RESP=",ut_getrespstr(MyRespID));
				}
				alldone = TRUE;
			}
			else if (MyCmdpkt->cmdID == UT_IND_OUTPUT)
			{
				/* Moderately surprising. *Log output.*/
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD: OUTPUT CMD RECEIVED=",ut_getrespstr(MyRespID));
				myrc = ut_process_output_ind_h(MyCmdpkt);
			}
			else
			{
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD: BAD:Cmd=",ut_getcmdstr(MyCmdpkt->cmdID));
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD: BAD:RESP=",ut_getrespstr(MyRespID));
				alldone = TRUE;
				myrc = ERR_GENERAL;
			}
		}
		else
		{
			UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"SHUTDOWN_CMD:"," Response failed. all done.");
			alldone = TRUE; /* Bail.*/
		}

		if (MyCmdpkt != NULL)
		{
			ut_free_pktdata(MyCmdpkt);
			MyCmdpkt = NULL;
		}

	} /* end while not alldone;*/

	return myrc;
}


/* Send RUNTEST cmd, and wait until _FINISHED recieved.*/
int ut_runtest_cmd_h( int connfd, const char* testFunName, const char* fileName, int *pRetval)
{
	int myrc = OK;
	CmdPacketData *MyCmdpkt = NULL;
	ut_proto_resp_t MyRespID = UT_RESP_NONE;
	char alldone = FALSE;

	if (tgt_is_alive() == FALSE)
	{
		UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD:"," Target Comm failed. all done.");
		myrc = ERR_GENERAL;
		return myrc; /* No target, no continue.*/
	}

	if (NULL == (MyCmdpkt = ut_alloc_pktdata(UT_SMALL_CMD_BUFFSIZE+DIGI_STRLEN((const sbyte *)testFunName))))
	{
		myrc = ERR_MEM_ALLOC_FAIL;
		return myrc; /* No memory, no continue.*/
	}
	MyCmdpkt->cmdID = UT_CMD_RUNTEST;

	sprintf(MyCmdpkt->argbuff,"%s",testFunName);
	MyCmdpkt->argbufflen = DIGI_STRLEN((const sbyte *)MyCmdpkt->argbuff);

	if (myrc == OK)
	{
		UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD:"," Sending...");
		myrc = ut_writecmd_to_socket(connfd, MyCmdpkt);
		ut_free_pktdata(MyCmdpkt);
		MyCmdpkt = NULL;
	}

	if (myrc != OK)
	{
		UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD:"," Send failed. all done.");
		alldone = TRUE; /* Bail.*/
	}
	else
	{
		alldone = FALSE;
	}

	while (alldone != TRUE)
	{
		if (myrc == OK)
		{
			myrc = ut_getcmdresponse_from_socket(connfd, &MyRespID, &MyCmdpkt);
		}

		if ( (myrc == OK) && (MyCmdpkt != NULL))
		{
			if (MyCmdpkt->cmdID == UT_CMD_RUNTEST)
			{
				/* Good. It's what we expected.*/
				if (MyRespID == UT_RESP_OK)
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: GOOD:RESP=",ut_getrespstr(MyRespID));
					alldone = FALSE; /* Wait for FINISH.*/
				}
				else if (MyRespID == UT_RESP_FINISHED)
				{
					if (0 == DIGI_STRCMP((sbyte *)MyCmdpkt->argbuff,(sbyte *)UT_PKT_TEST_PASS_STR))
					{
						UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: (PASS) GOOD:RESP=",ut_getrespstr(MyRespID));
						*pRetval = 0;
					}
					else
					{
						UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: (FAIL) GOOD:RESP=",ut_getrespstr(MyRespID));
						*pRetval = 1;
					}
					alldone = TRUE;
				}
				else if (MyRespID == UT_RESP_FAILED)
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: GOOD:RESP=",ut_getrespstr(MyRespID));
					*pRetval = 1;
					alldone = TRUE;
				}
				else
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: BAD:RESP=",ut_getrespstr(MyRespID));
					*pRetval = 1;
					alldone = TRUE;
				}
			}
			else if (MyCmdpkt->cmdID == UT_IND_OUTPUT)
			{
            /* Moderately surprising. *Log output. */
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: OUTPUT CMD RECEIVED=",ut_getrespstr(MyRespID));
				myrc = ut_process_output_ind_h(MyCmdpkt);
			}
			else
			{
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: BAD:Cmd=",ut_getcmdstr(MyCmdpkt->cmdID));
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD: BAD:RESP=",ut_getrespstr(MyRespID));
				alldone = TRUE;
				myrc = ERR_GENERAL;
			}
		}
		else
		{
			UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_CMD:"," Response failed. all done.");
			alldone = TRUE; /* Bail.*/
		}

		if (MyCmdpkt != NULL)
		{
			ut_free_pktdata(MyCmdpkt);
			MyCmdpkt = NULL;
		}

	} /* end while not alldone;*/

	return myrc;
}


/* Process incoming Log output. Typically during RUNTEST cmd processing.*/
int ut_process_output_ind_h( CmdPacketData *pPktData)
{

	if ((pPktData == NULL) || (pPktData->argbuff == NULL))
		return OK;
	else
		unittest_write(pPktData->argbuff);
	return OK;
}



/****************************************
 Target side
******************************************/
#if 1

typedef struct RebootThreadWorkArea
{
	RTOS_THREAD    threadptr;
	TCP_SOCKET     listenSocket;
	TCP_SOCKET     clientSocket;
} RebootThreadWorkArea;

static RebootThreadWorkArea reboot_wa;

static int ut_platform_reboot(char startagain)
{

	if (startagain == TRUE)
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"ut_platform_reboot:: Going down now! ","STARTAGAIN = TRUE");
		#if defined(__RTOS_VXWORKS__)
        /* KRB: Need code here... Do whatever is needed to restart this platform. e.g. shutdown -r*/
			reboot(0x2);
		#elif defined(__RTOS_LINUX__) || defined( __RTOS_SOLARIS__)
			/* KRB: Need code here... Do whatever is needed to restart this platform. e.g. shutdown -r*/
			/* KRB: Stub that just exit's this process, doesn't reboot the machine.*/
			exit(0);
		#endif
	}
	else
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"ut_platform_reboot:: Going down now! ","STARTAGAIN = FALSE");
		#if defined(__RTOS_VXWORKS__)
        /* KRB: Need code here... Do whatever is needed to restart this platform. e.g. shutdown -r*/
		#elif defined(__RTOS_LINUX__) || defined( __RTOS_SOLARIS__)
			exit(0);
		#endif
	}

	return 0;
	UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"ut_platform_reboot:: ","Going down now! Done.");
}

static void rebootThreadMain(void* context)
{
	RebootThreadWorkArea *pWA = (RebootThreadWorkArea *)context;
	int myrc = OK;
    const ubyte2    serverPort = UT_TGT_REBOOT_PORTID;
    intBoolean isBreakSignalRequest = FALSE;
    sbyte4 i = 0;
    char stop_now = FALSE;
    char golisten_now = FALSE;

    static char dbgbuff[80];

    char readstring[80];
    char expectstring[80];
    int expectlen = 0;
    unsigned int bytesread = 0;
    int cmpresult = 0;
    int myoklen = 0;

    UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain:: ","Starting...");

    sprintf(expectstring,"%s%s%s",UT_PKT_MO_HEAD_STR,UT_PKT_REBOOT_STR,UT_PKT_MO_TAIL_STR);
    expectlen = DIGI_STRLEN((sbyte *)expectstring);

    while (stop_now != TRUE)
    {
 		/* Create Listener port and listen for incoming connections.*/
		UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain:: ","Listen()...");
		myrc = TCP_LISTEN_SOCKET(&pWA->listenSocket, serverPort);

		if (myrc == OK)
		{
			UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain:: ","Accept()...");
			myrc = TCP_ACCEPT_SOCKET(&pWA->clientSocket, pWA->listenSocket, &isBreakSignalRequest);
			if (myrc == OK)
			{
			   	golisten_now = FALSE;
			    while (golisten_now != TRUE)
			    {
			    	i++;
			    	/* Go see if there's a reboot command out there...*/
			    	UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain: ","Wait for Reboot Cmd.");

			    	/* Read and process the header.*/
			    	myrc = tcp_read_avail(pWA->clientSocket,(sbyte *)readstring, expectlen, &bytesread, CMD_RECEIPT_TIMEOUT_TGT); /*KRB: Was TCP_NO_TIMEOUT. I think it is OK/better to timeout since we will go listen again...*/
			    	if (bytesread != expectlen)
			    	{
						myrc = tgt_read_failure(myrc, CMD_RECEIPT_TIMEOUT_TGT, bytesread, expectlen);
			    	}
			    	else
			    	{
			    		readstring[bytesread] = '\0';
						cmpresult = DIGI_MEMCMP((ubyte *)expectstring, (ubyte *)readstring, expectlen, &cmpresult);
			    	}
					if ((myrc != OK) || (cmpresult != 0))
					{
						UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain: BogusRebootCmd=",readstring);
						myrc = ERR_TCP_READ_ERROR;
				    	golisten_now = TRUE;
				    	/* If anything bad  just go listen again..*/
					}
					else
					{
				    	UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain: Recv:: RebootCmd=",readstring);

				    	/* Send Ack.*/
				    	sprintf(readstring,"%s%s%s",UT_PKT_MO_HEAD_STR, UT_PKT_REBOOT_OK_STR, UT_PKT_MO_TAIL_STR);
					    myoklen = DIGI_STRLEN((sbyte *)readstring);

						TCP_WRITE_ALL(pWA->clientSocket,(sbyte *)readstring, myoklen, &bytesread); /* just re-using variables...*/

				    	golisten_now = TRUE; /* If we are rebooting, quit this thread too... if possible.*/
						stop_now = TRUE;     /* If we are rebooting, quit this thread too... if possible.*/

						myrc = ut_platform_reboot(TRUE);  /* KRB: At some point we may want to parse for parameters...*/

					}

			    } /* end while (golisten_now != TRUE)*/
				TCP_CLOSE_SOCKET(pWA->clientSocket);
				pWA->clientSocket = 0;
			}
			RTOS_sleepMS((1000/4)); /* A little delay in case someone is hammering us.*/
		}
		else
		{
			sprintf(dbgbuff,"%d",myrc);
  		    UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain:: Listen Failed rc = ",dbgbuff);
			stop_now = TRUE;
		}

		TCP_CLOSE_SOCKET(pWA->listenSocket);
		pWA->listenSocket = 0;

    } /* end while (stop_new != TRUE)*/

    UT_DEBUG_PRINT(UT_DBG_COMM_REBOOT,"rebootThreadMain:: ","Done. Exit.");

}


static int ut_start_reboot_listener_tgt(void)
{
	int rc = OK;

	/* Init our globals before starting the reboot listener.*/
    DIGI_MEMSET((ubyte *)&reboot_wa, 0, sizeof(reboot_wa));

	/* Start the listener thread.*/
    rc = RTOS_createThread(rebootThreadMain, &reboot_wa, (sbyte4)DEBUG_CONSOLE, &reboot_wa.threadptr);

    return rc;
}
/* extern MSTATUS VXWORKS_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)*/

static int ut_stop_reboot_listener_tgt(void)
{
	/* Kill him.*/
	if (reboot_wa.threadptr)
	{
		RTOS_destroyThread(reboot_wa.threadptr);
		reboot_wa.threadptr = NULL;
	}

	/* This code assumes that there's no socket ownership per thread.*/
	if (reboot_wa.listenSocket)
	{
		TCP_CLOSE_SOCKET(reboot_wa.listenSocket);
		reboot_wa.listenSocket = 0;

	}
	if (reboot_wa.clientSocket)
	{
		TCP_CLOSE_SOCKET(reboot_wa.clientSocket);
		reboot_wa.clientSocket = 0;
	}

	return 0;
}

#else
/* Stub versions*/
static int ut_start_reboot_listener_tgt(void) {	return 0; }
static int ut_stop_reboot_listener_tgt(void) {	return 0; }
#endif


/* Listen for incoming connections, and accept, returning connected socket.*/
int ut_initcomm_tgt( struct sockaddr *phostip, int *pconnfd)
{
	int myrc = OK;
    TCP_SOCKET      listenSocket, clientSocket;
    const ubyte2    serverPort = UT_TGT_PORTID;
    intBoolean isBreakSignalRequest = FALSE;

    /*KRB: Makes Sig-HUP not work....*/
    /*KRB: TCP_INIT();    Need to do this somewhere.*/
	set_tgt_is_alive(FALSE); /* This flag isn't really used on the target side, but for cleanliness.*/

	ut_start_reboot_listener_tgt();

	UT_DEBUG_PRINT(UT_DBG_COMM_V,"ut_initcomm_tgt:: ","Listen()...");
	myrc = TCP_LISTEN_SOCKET(&listenSocket, serverPort);

	if (myrc == OK)
	{
		UT_DEBUG_PRINT(UT_DBG_COMM_V,"ut_initcomm_tgt:: ","Accept()...");
		myrc = TCP_ACCEPT_SOCKET(&clientSocket, listenSocket, &isBreakSignalRequest);
		if (myrc == OK)
		{
			*pconnfd = clientSocket;
			set_tgt_is_alive(TRUE); /* This flag isn't really used on the target side, but for cleanliness.*/
		}
	}

	TCP_CLOSE_SOCKET(listenSocket);

	return myrc;
}

int ut_write_output_cmd_tgt(int connfd, const char *msg)
{
	int myrc = OK;
	CmdPacketData *MyCmdpkt = NULL;
	int len = 0;

	if (msg == NULL)
		return ERR_NULL_POINTER;

	len = DIGI_STRLEN((sbyte *)msg);
	if (len == 0)
		return ERR_NULL_POINTER;

	if (NULL == (MyCmdpkt = ut_alloc_pktdata(len)))
	{
		myrc = ERR_MEM_ALLOC_FAIL;
		return myrc; /* No memory, no continue.*/
	}
	MyCmdpkt->cmdID = UT_IND_OUTPUT;
	MyCmdpkt->argbufflen = len;
	myrc = DIGI_MEMCPY(MyCmdpkt->argbuff, msg, len);

	if (myrc == OK)
	{
		myrc = ut_writecmd_to_socket(connfd, MyCmdpkt);
		ut_free_pktdata(MyCmdpkt);
		MyCmdpkt = NULL;
	}
	return 0;
}

int ut_waitfor_startup_cmd_tgt(int connfd)
{
	int myrc = OK;
	CmdPacketData *MyCmdpkt = NULL;
	ut_proto_resp_t MyRespID = UT_RESP_NONE;

	UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_TGT: ","Wait for Startup Cmd.");
	myrc = ut_getcmd_from_socket(connfd, &MyCmdpkt);
	if ( (myrc == OK) && (MyCmdpkt != NULL) )
	{
		if (MyCmdpkt->cmdID == UT_CMD_STARTUP)
		{
			UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_TGT: ","Good");
			/* Send my response...*/
			MyRespID = UT_RESP_OK;
			MyCmdpkt->argbufflen = 0;
			MyCmdpkt->argbuff[MyCmdpkt->argbufflen] = '\0';
			myrc = ut_writeresponse_to_socket(connfd, MyCmdpkt, MyRespID);
		}
		else
		{
			UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"STARTUP_TGT: BAD:Cmd=",ut_getcmdstr(MyCmdpkt->cmdID));
			myrc = ERR_GENERAL;
		}
	}

	if (MyCmdpkt != NULL)
	{
		ut_free_pktdata(MyCmdpkt);
		MyCmdpkt = NULL;
	}

	return myrc;
}

int ut_waitfor_runtest_cmd_tgt(int connfd, TestDescriptor* tests, int num_tests)
{
	int myrc = OK;
	CmdPacketData *MyCmdpkt = NULL;
	ut_proto_resp_t MyRespID = UT_RESP_NONE;
	char alldone = FALSE;
	int testindex = -1;
	int RetVal = 0;
	TestFun testFun;

	char testfunname[MAX_TEST_NAME_LEN];

    /*cdsxxx  hack FIXME*/
    /*Make sure the NFS mounted filesystem is being used*/
#if defined(__RTOS_VXWORKS__)
    cd("/home/8555-3/test");
PRINTF("Changing directory to /home/8555-3/test\n");
#endif


	while (alldone != TRUE)
	{
		myrc = ut_getcmd_from_socket(connfd, &MyCmdpkt);
		if ( (myrc == OK) && (MyCmdpkt != NULL) )
		{
			if (MyCmdpkt->cmdID == UT_CMD_RUNTEST)
			{
				sprintf(testfunname,"%s",MyCmdpkt->argbuff);
				testindex = ut_testindexfromstr(tests, num_tests, testfunname);

				ut_free_pktdata(MyCmdpkt);
				MyCmdpkt = NULL;

				if (NULL == (MyCmdpkt = ut_alloc_pktdata(MAX_TEST_NAME_LEN+40)))  /* Enough room for Failure args..*/
				{
					myrc = ERR_MEM_ALLOC_FAIL;
					return myrc; /* No memory, no continue.*/
				}
				MyCmdpkt->cmdID = UT_CMD_RUNTEST;

				if (testindex >= 0)
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_TGT: RUN_TEST: (OK)",testfunname);
					/* No ARGS on OK.*/
					MyCmdpkt->argbufflen = 0;
					MyCmdpkt->argbuff[MyCmdpkt->argbufflen] = '\0';
					MyRespID = UT_RESP_OK;
					myrc = ut_writeresponse_to_socket(connfd, MyCmdpkt, MyRespID);

				    PRINTF("Running test %s\n", testfunname);
				    testFun = tests[testindex].testFun;
				    RetVal = testFun();

				    /* Tell host side PASS or FAIL for this test.*/
				    if (RetVal == 0)
						sprintf(MyCmdpkt->argbuff,"%s",UT_PKT_TEST_PASS_STR);
				    else
						sprintf(MyCmdpkt->argbuff,"%s",UT_PKT_TEST_FAIL_STR);
				    MyCmdpkt->argbufflen = DIGI_STRLEN((const sbyte *)MyCmdpkt->argbuff);
				    PRINTF("Test %s %s\n",testfunname,MyCmdpkt->argbuff);

					MyRespID = UT_RESP_FINISHED;
					myrc = ut_writeresponse_to_socket(connfd, MyCmdpkt, MyRespID);

				}
				else
				{
					UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_TGT: RUN_TEST: (FAILED) Test Not Found: ",testfunname);
					/* Tell him why it failed.*/
					sprintf(MyCmdpkt->argbuff,"%s%s","Test Not Found: ",testfunname);
					MyCmdpkt->argbufflen = DIGI_STRLEN((const sbyte *)MyCmdpkt->argbuff);
					MyRespID = UT_RESP_FAILED;
					myrc = ut_writeresponse_to_socket(connfd, MyCmdpkt, MyRespID);
				}

			}
			else if (MyCmdpkt->cmdID == UT_CMD_SHUTDOWN)
			{
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_TGT: DONE:Cmd=",ut_getcmdstr(MyCmdpkt->cmdID));
				/* No ARGS on OK.*/
				MyCmdpkt->argbufflen = 0;
				MyCmdpkt->argbuff[MyCmdpkt->argbufflen] = '\0';
				MyRespID = UT_RESP_OK;
				myrc = ut_writeresponse_to_socket(connfd, MyCmdpkt, MyRespID);
				alldone = TRUE;
			}
			else
			{
				UT_DEBUG_PRINT(UT_DBG_CMD_RESP,"RUNTEST_TGT: BAD:Cmd=",ut_getcmdstr(MyCmdpkt->cmdID));
				myrc = ERR_GENERAL;
				alldone = TRUE;
			}
		} /* Endif good receive of a CMD. */

		if (MyCmdpkt != NULL)
		{
			ut_free_pktdata(MyCmdpkt);
			MyCmdpkt = NULL;
		}
		if (myrc != OK)
			alldone = TRUE;
	} /* End while forever... */

	return myrc;
}

int ut_stopcomm_tgt( int *pconnfd, int statusin)
{
	int myrc;
	myrc = TCP_CLOSE_SOCKET(*pconnfd);
	*pconnfd = 0;
	return myrc;

#if defined(__RTOS_VXWORKS__)
	/* Don't stop the reboot thread in VxWorks. */
#elif defined(__RTOS_LINUX__) || defined( __RTOS_SOLARIS__)
	/* Go ahead and stop the reboot thread in Linux. */
	ut_stop_reboot_listener_tgt();
#endif


}


#endif  /*  __UNITTEST_REMOTE_SUPPORT__ */
