#ifndef WEBSOCKET_TEST_MOCKS_H
#define WEBSOCKET_TEST_MOCKS_H

#include "common/moptions.h"
#include "common/mdefs.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mtcp.h"
#include "common/random.h"

#define WS_TEST_MAX_READS 32
#define WS_TEST_MAX_READ_SIZE 2048
#define WS_TEST_MAX_RANDOM_SIZE 16
#define WS_TEST_MAX_WRITES 4096
#define WS_TEST_RNG_FAILURE (-25100)

void ws_test_mocks_reset(void);
void ws_test_set_random(const ubyte *pBytes, ubyte4 len, MSTATUS status);
int ws_test_queue_read(MSTATUS status, const ubyte *pBytes, ubyte4 len);
void ws_test_set_write_result(MSTATUS status, ubyte4 maxBytesWritten);

const ubyte *ws_test_written_data(void);
ubyte4 ws_test_written_len(void);
ubyte4 ws_test_write_calls(void);

#endif
