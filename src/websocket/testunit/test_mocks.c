#if !defined(NANOWS_UNIT_TEST_MOCKS)
#error "NanoWS mocks must only be compiled by the websocket_test_mocks test target"
#endif

#include "test_mocks.h"

#include <limits.h>
#include <string.h>

#include "ssl/ssl.h"

typedef struct
{
    MSTATUS status;
    ubyte4 len;
    ubyte data[WS_TEST_MAX_READ_SIZE];
} WsTestRead;

static WsTestRead g_reads[WS_TEST_MAX_READS];
static ubyte4 g_readCount;
static ubyte4 g_readIndex;
static ubyte g_randomBytes[WS_TEST_MAX_RANDOM_SIZE];
static ubyte4 g_randomLen;
static ubyte4 g_randomOffset;
static MSTATUS g_randomStatus;
static MSTATUS g_writeStatus;
static ubyte4 g_writeLimit;
static ubyte g_written[WS_TEST_MAX_WRITES];
static ubyte4 g_writtenLen;
static ubyte4 g_writeCalls;

/* Clears queued reads, written bytes, RNG and write settings between tests. */
void ws_test_mocks_reset(void)
{
    ubyte4 i;

    memset(g_reads, 0, sizeof(g_reads));
    g_readCount = 0;
    g_readIndex = 0;
    for (i = 0; i < sizeof(g_randomBytes); i++)
    {
        g_randomBytes[i] = (ubyte)i;
    }
    g_randomLen = sizeof(g_randomBytes);
    g_randomOffset = 0;
    g_randomStatus = OK;
    g_writeStatus = OK;
    g_writeLimit = UINT_MAX;
    memset(g_written, 0, sizeof(g_written));
    g_writtenLen = 0;
    g_writeCalls = 0;
}

/* Sets the bytes (cycled) and status returned by the RNG; invalid input restores the default sequence. */
void ws_test_set_random(const ubyte *pBytes, ubyte4 len, MSTATUS status)
{
    ubyte4 i;

    g_randomStatus = status;
    g_randomOffset = 0;
    if (NULL == pBytes || 0 == len || len > sizeof(g_randomBytes))
    {
        for (i = 0; i < sizeof(g_randomBytes); i++)
        {
            g_randomBytes[i] = (ubyte)i;
        }
        g_randomLen = sizeof(g_randomBytes);
        return;
    }

    memcpy(g_randomBytes, pBytes, len);
    g_randomLen = len;
}

/* Queues one read result for the next TCP/SSL read; returns 0 if the queue or size limit is exceeded. */
int ws_test_queue_read(MSTATUS status, const ubyte *pBytes, ubyte4 len)
{
    WsTestRead *pRead;

    if (g_readCount >= WS_TEST_MAX_READS || len > WS_TEST_MAX_READ_SIZE ||
        (len > 0 && NULL == pBytes))
    {
        return 0;
    }

    pRead = &g_reads[g_readCount++];
    pRead->status = status;
    pRead->len = len;
    if (len > 0)
    {
        memcpy(pRead->data, pBytes, len);
    }

    return 1;
}

/* Makes writes return status, or accept at most maxBytesWritten bytes per call to simulate a short write. */
void ws_test_set_write_result(MSTATUS status, ubyte4 maxBytesWritten)
{
    g_writeStatus = status;
    g_writeLimit = maxBytesWritten;
}

/* Returns all bytes written so far, in order. */
const ubyte *ws_test_written_data(void)
{
    return g_written;
}

/* Returns the total number of bytes written so far. */
ubyte4 ws_test_written_len(void)
{
    return g_writtenLen;
}

/* Returns how many times a write was attempted, including failed ones. */
ubyte4 ws_test_write_calls(void)
{
    return g_writeCalls;
}

/* Replaces the real RNG: fills the buffer from the configured bytes, or returns the configured error. */
MSTATUS RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize)
{
    sbyte4 i;

    (void)pRandomContext;
    if (OK != g_randomStatus)
    {
        return g_randomStatus;
    }
    if (NULL == pBuffer || bufSize < 0 || 0 == g_randomLen)
    {
        return ERR_NULL_POINTER;
    }

    for (i = 0; i < bufSize; i++)
    {
        pBuffer[i] = g_randomBytes[g_randomOffset++ % g_randomLen];
    }

    return OK;
}

/* Returns the next queued read, or ERR_TCP_READ_TIMEOUT once the queue is empty.
   mtcp.h expands this name to the platform backend symbol that libnanows calls. */
MSTATUS TCP_READ_AVL_EX(
    TCP_SOCKET socket,
    sbyte *pBuffer,
    ubyte4 maxBytesToRead,
    ubyte4 *pNumBytesRead,
    ubyte4 msTimeout)
{
    WsTestRead *pRead;

    (void)socket;
    (void)msTimeout;
    if (NULL == pBuffer || NULL == pNumBytesRead)
    {
        return ERR_NULL_POINTER;
    }
    *pNumBytesRead = 0;
    if (g_readIndex >= g_readCount)
    {
        return ERR_TCP_READ_TIMEOUT;
    }

    pRead = &g_reads[g_readIndex++];
    if (OK != pRead->status)
    {
        return pRead->status;
    }
    if (pRead->len > maxBytesToRead)
    {
        return ERR_TCP_READ_ERROR;
    }
    if (pRead->len > 0)
    {
        memcpy(pBuffer, pRead->data, pRead->len);
    }
    *pNumBytesRead = pRead->len;
    return OK;
}

/* Records written bytes instead of sending them, honouring the configured error and short-write limit. */
MSTATUS TCP_WRITE(
    TCP_SOCKET socket,
    sbyte *pBuffer,
    ubyte4 numBytesToWrite,
    ubyte4 *pNumBytesWritten)
{
    ubyte4 n;

    (void)socket;
    g_writeCalls++;
    if (NULL == pBuffer || NULL == pNumBytesWritten)
    {
        return ERR_NULL_POINTER;
    }
    *pNumBytesWritten = 0;
    if (OK != g_writeStatus)
    {
        return g_writeStatus;
    }

    n = numBytesToWrite;
    if (n > g_writeLimit)
    {
        n = g_writeLimit;
    }
    if (n > WS_TEST_MAX_WRITES - g_writtenLen)
    {
        return ERR_TCP_WRITE_ERROR;
    }
    memcpy(g_written + g_writtenLen, pBuffer, n);
    g_writtenLen += n;
    *pNumBytesWritten = n;
    return OK;
}

/* TLS send stub: reuses the TCP write mock and returns the byte count or an error. */
sbyte4 SSL_send(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize)
{
    ubyte4 written = 0;
    MSTATUS status;

    (void)connectionInstance;
    if (bufferSize < 0)
    {
        return ERR_BAD_LENGTH;
    }
    status = TCP_WRITE(0, pBuffer, (ubyte4)bufferSize, &written);
    return (OK == status) ? (sbyte4)written : status;
}

/* TLS receive stub: reuses the TCP read mock, so queued reads and timeouts behave the same. */
sbyte4 SSL_recv(
    sbyte4 connectionInstance,
    sbyte *pRetBuffer,
    sbyte4 bufferSize,
    sbyte4 *pNumBytesReceived,
    ubyte4 timeout)
{
    ubyte4 bytesRead = 0;
    MSTATUS status;

    (void)connectionInstance;
    if (bufferSize < 0 || NULL == pNumBytesReceived)
    {
        return ERR_BAD_LENGTH;
    }
    status = TCP_READ_AVL_EX(
        0, pRetBuffer, (ubyte4)bufferSize, &bytesRead, timeout);
    *pNumBytesReceived = (sbyte4)bytesRead;
    return status;
}
