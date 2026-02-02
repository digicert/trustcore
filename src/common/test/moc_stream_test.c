/*
 * moc_stream_test.c
 *
 * Mocana Simple Stream Test
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
#include "../../common/random.h"
#include "../../common/moc_stream.h"

/* #include "../moc_stream.c"  */

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__)
#include <stdio.h>
#include <string.h>
#define PRINTF1      printf
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF1(X)
#define PRINTF2(X,Y)
#define PRINTF3(X,Y,Z)
#endif


/*---------------------------------------------------------------------------*/

#define TEST_IT(X)      if (X) { error_line = __LINE__; status = (OK > status) ? status : -1; goto exit; } numTests++
static int error_line = 0;
static int numTests = 0;


/*------------------------------------------------------------------*/

#define TEST_BUF_SIZE   16384
#define STREAM_BUF_SIZE 0x80

static ubyte beforeBuffer[TEST_BUF_SIZE];
static ubyte afterBuffer[TEST_BUF_SIZE];
static sbyte4 mCOUNT;
static sbyte4 mINDEX;
static randomContext* pRandomContext = NULL;


/*------------------------------------------------------------------*/

static MSTATUS
initTest(void)
{
    MSTATUS        status;

    /* initialize buffers, to prevent false positives */
    DIGI_MEMSET(beforeBuffer, 0x5c, TEST_BUF_SIZE);
    DIGI_MEMSET(afterBuffer,  0x00, TEST_BUF_SIZE);

    status = RANDOM_numberGenerator(pRandomContext, beforeBuffer, TEST_BUF_SIZE);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
streamWriteData(void* outStream,
                ubyte *pBufferToSend, ubyte4 numBytesToWrite,
                ubyte4 *pNumBytesWritten)
{
    static int writeByte = 0;
    MSTATUS status = OK;
    MOC_UNUSED(outStream);

    TEST_IT(0 == numBytesToWrite);

    writeByte++;
    *pNumBytesWritten = 0;

    if (!(writeByte & 0x07))      /* write a byte once every 7th attempt */
    {
        sbyte4 loop;

        for (loop = 0; ((loop < mCOUNT) && (numBytesToWrite)); loop++)
        {
            afterBuffer[mINDEX++] = *pBufferToSend;
            (*pNumBytesWritten)++;
            numBytesToWrite--;
            pBufferToSend++;
        }
    }

exit:
    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
DIGI_STREAM_TEST_testIt(void)
{
    ubyte4       buf_offset      = 0;
    ubyte4       buf_size        = TEST_BUF_SIZE;
    streamDescr* pStreamDescr    = NULL;
    ubyte4       numBytesWritten = 0;
    intBoolean   isFlushComplete = FALSE;
    sbyte4       result;
    MSTATUS      status = OK;

    TEST_IT(OK > (status = initTest()));

    TEST_IT(OK > (status = DIGI_STREAM_open(&pStreamDescr, 0, STREAM_BUF_SIZE, streamWriteData)));

    do
    {
        numBytesWritten = 0;

        if (buf_size - buf_offset)
            TEST_IT(OK > (status = DIGI_STREAM_write(pStreamDescr, beforeBuffer + buf_offset, buf_size - buf_offset, &numBytesWritten)));

        if (0 == numBytesWritten)
        {
            DIGI_STREAM_flush(pStreamDescr, NULL, &isFlushComplete);
        }
        else
        {
            buf_offset += numBytesWritten;
        }
    }
    while ((TEST_BUF_SIZE > buf_offset) || (FALSE == isFlushComplete));

    DIGI_MEMCMP(beforeBuffer, afterBuffer, TEST_BUF_SIZE, &result);

    TEST_IT(0 != result);

    status = DIGI_STREAM_close(&pStreamDescr);

exit:
    if (OK > status)
        PRINTF2("DIGI_STREAM_TEST_testIt: error, status = %d\n", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

int moc_stream_test_all()
{
    MSTATUS status = OK;

    TEST_IT(status = RANDOM_acquireContext(&pRandomContext));

    for (mCOUNT = 1; mCOUNT < STREAM_BUF_SIZE; mCOUNT++)
    {
        mINDEX = 0;

        if (OK > (status = DIGI_STREAM_TEST_testIt()))
            break;
    }

exit:
    if (pRandomContext)
        RANDOM_releaseContext(&pRandomContext);

    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        PRINTF3("\nmoc_stream_test_all: status = %d, error at line #%d\n", (int)status, error_line);
        status = 1;
    }

    return status;
}


//int main(int argc, char* argv[])
//{
//    return mstdlib_test_all();
//}
