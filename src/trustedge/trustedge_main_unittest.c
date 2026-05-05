/*
 * trustedge_main_unittest.c
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#include "trustedge_main.c"
#include "trustedge_main_unittest.h"
#include "../common/mocana.h"

#include "../../unit_tests/unittest.h"

sbyte *gpExpectedHelp =
    "Usage: trustedge [options] <command> [<args>]\n"
    "\n"
    "TrustEdge command line tool\n"
    "\n"
    "Options:\n"
    "  --help          Display usage information\n"
    "  --version       Display TrustEdge version\n"
    "\n"
    "Commands:\n"
    "  agent           Agent mode - connected to Device Trust Manager\n"
    "  mqtt            MQTT client for pub/sub\n"
    "  certificate     Certificate mode\n";

sbyte *gpExpectedHelpNoArg =
    "Usage: trustedge [options] <command> [<args>]\n"
    "\n"
    "TrustEdge command line tool\n"
    "\n"
    "Options:\n"
    "  --help          Display usage information\n"
    "  --version       Display TrustEdge version\n"
    "\n"
    "Commands:\n"
    "  agent           Agent mode - connected to Device Trust Manager\n"
    "  mqtt            MQTT client for pub/sub\n"
    "  certificate     Certificate mode\n"
    "\n"
    "ERROR: No arguments provided, status = ERR_TRUSTEDGE_NO_ARG (-22601)\n";

sbyte *gpExpectedInvalidHelp =
    "Usage: trustedge [options] <command> [<args>]\n"
    "\n"
    "TrustEdge command line tool\n"
    "\n"
    "Options:\n"
    "  --help          Display usage information\n"
    "  --version       Display TrustEdge version\n"
    "\n"
    "Commands:\n"
    "  agent           Agent mode - connected to Device Trust Manager\n"
    "  mqtt            MQTT client for pub/sub\n"
    "  certificate     Certificate mode\n"
    "\n"
    "ERROR: Argument \"--invalid\" not recognized, status = ERR_TRUSTEDGE_UNKNOWN_ARG (-22602)\n";

int trustedge_main_unittest_no_args()
{
    int retVal = 0;
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    sbyte4 cmpRes = -1;

    REDIRECT_OUTPUT(__func__)
    status = TRUSTEDGE_main(0, NULL);
    RESTORE_OUTPUT

    UNITTEST_GOTO(status != -1, retVal, exit)

    status = DIGICERT_readFile(__func__, &pData, &dataLen);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)

    if (DIGI_STRLEN(gpExpectedHelpNoArg) != dataLen)
    {
        status = ERR_BAD_LENGTH;
        UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    }

    status = DIGI_MEMCMP(gpExpectedHelpNoArg, pData, dataLen, &cmpRes);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    UNITTEST_GOTO(cmpRes != 0, retVal, exit)

exit:

    DIGI_FREE((void **) &pData);

    return retVal;
}

int trustedge_main_unittest_invalid_arg()
{
    int retVal = 0;
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    sbyte4 cmpRes = -1;
    char *ppArgv[] = {
        "trustedge",
        "--invalid"
    };

    REDIRECT_OUTPUT(__func__)
    status = TRUSTEDGE_main(COUNTOF(ppArgv), ppArgv);
    RESTORE_OUTPUT

    UNITTEST_GOTO(status != -1, retVal, exit)

    status = DIGICERT_readFile(__func__, &pData, &dataLen);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)

    if (DIGI_STRLEN(gpExpectedInvalidHelp) != dataLen)
    {
        status = ERR_BAD_LENGTH;
        UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    }

    status = DIGI_MEMCMP(gpExpectedInvalidHelp, pData, dataLen, &cmpRes);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    UNITTEST_GOTO(cmpRes != 0, retVal, exit)

exit:

    DIGI_FREE((void **) &pData);

    return retVal;
}

int trustedge_main_unittest_help()
{
    int retVal = 0;
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    sbyte4 cmpRes = -1;
    char *ppArgv[] = {
        "trustedge",
        "--help"
    };

    REDIRECT_OUTPUT(__func__)
    status = TRUSTEDGE_main(COUNTOF(ppArgv), ppArgv);
    RESTORE_OUTPUT

    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)

    status = DIGICERT_readFile(__func__, &pData, &dataLen);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)

    if (DIGI_STRLEN(gpExpectedHelp) != dataLen)
    {
        status = ERR_BAD_LENGTH;
        UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    }

    status = DIGI_MEMCMP(gpExpectedHelp, pData, dataLen, &cmpRes);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    UNITTEST_GOTO(cmpRes != 0, retVal, exit)

exit:

    DIGI_FREE((void **) &pData);

    return retVal;
}

int trustedge_main_unittest_version()
{
    int retVal = 0;
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    sbyte4 cmpRes = -1;
    char *ppArgv[] = {
        "trustedge",
        "--version"
    };
    ubyte *pExpected = NULL;
    ubyte4 expectedLen = 0;

    REDIRECT_OUTPUT(__func__)
    BUILD_INFO_print();
    RESTORE_OUTPUT

    status = DIGICERT_readFile(__func__, &pExpected, &expectedLen);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)

    REDIRECT_OUTPUT(__func__)
    status = TRUSTEDGE_main(COUNTOF(ppArgv), ppArgv);
    RESTORE_OUTPUT

    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)

    status = DIGICERT_readFile(__func__, &pData, &dataLen);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)

    if (expectedLen != dataLen)
    {
        status = ERR_BAD_LENGTH;
        UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    }

    status = DIGI_MEMCMP(pExpected, pData, dataLen, &cmpRes);
    UNITTEST_STATUS_GOTO(__MOC_LINE__, status, retVal, exit)
    UNITTEST_GOTO(cmpRes != 0, retVal, exit)

exit:

    DIGI_FREE((void **) &pExpected);
    DIGI_FREE((void **) &pData);

    return retVal;
}
