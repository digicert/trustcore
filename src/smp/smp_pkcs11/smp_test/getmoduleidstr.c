/*
 * smp_pkcs11_getmoduleidstr.c
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
 * @file       smp_pkcs11_getmoduleidstr.c
 * @brief      Utility to list module ID.
 * @details    This utility returns the module id in string format that can be
               copied to the configuration file for unique identification of this
               module.
 */

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/mstdlib.h"
#include "../../../common/debug_console.h"
#include "../../smp.h"
#include "../../smp_interface.h"
#include "../smp_pkcs11_api.h"
#include "../smp_pkcs11_interface.h"
#include "../smp_pkcs11.h"

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#define PKCS11_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define PKCS11_DEBUG_PRINT_NO_ARGS(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define LOG_MESSAGE(fmt, ...) \
    do {\
        printf(fmt"\n", ##__VA_ARGS__);\
    } while (0)

#define LOG_MESSAGE_NONL(fmt, ...) \
    do {\
        printf(fmt, ##__VA_ARGS__);\
    } while (0)

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)

MSTATUS PKCS11_listModuleIdStrings(ubyte *pLibPath);

MSTATUS listModuleIdStrings(ubyte *pLibPath)
{
    MSTATUS status;

    status = PKCS11_init(NULL);
    if (OK != status)
    {
        LOG_ERROR("PKCS11_init failed with error code: %d\n", status);
        goto exit;
    }

    status = PKCS11_listModuleIdStrings(pLibPath);
    if (OK != status)
    {
        LOG_ERROR("PKCS11_listModuleIdStrings failed with error code: %d\n", status);
        goto exit;
    }

exit:

    (void) PKCS11_deInit();

    return status;
}

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
static void displayHelp(char *prog)
{
    printf(" Usage: %s <options>\n", prog);
    printf("  options:\n");
    printf("    -modulelibpath <path>        Required. Path to the pkcs11 shared library.\n");
    printf("\n");
    return;
}

static MSTATUS readArgs(int argc, char **ppArgv, ubyte **ppLibPath)
{
    sbyte4 i = 0;

    if (argc < 2)
    {
        displayHelp(ppArgv[0]);
        return -1;
    }

    for (i = 1; i < argc; i++)
    {
        if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-help") == 0)
        {
            displayHelp(ppArgv[0]);
            return -2;
        }
        else if (DIGI_STRCMP((const sbyte *)ppArgv[i],
            (const sbyte *)"-modulelibpath") == 0)
        {
            if (++i < argc)
            {
                *ppLibPath = (ubyte *) ppArgv[i];
            }
            continue;
        }
    }

    return OK;
}
#endif /* __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__ */

int main(int argc, char *argv[])
{
    int retVal = -1;
    ubyte *pLibPath = NULL;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    retVal = readArgs(argc, argv, &pLibPath);
    if (-2 == retVal)
    {
        return 0;
    }
    else if (retVal)
    {
        goto exit;
    }
#endif

    DIGICERT_initDigicert();

    retVal = listModuleIdStrings(pLibPath);

exit:

    if (0 != retVal)
        LOG_ERROR("***** Test execution failed *****");

    DIGICERT_freeDigicert();
    return retVal;
}
