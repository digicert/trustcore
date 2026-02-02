/*
 * fapi2_getcapability.c
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
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "../../../../common/moptions.h"
#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "../fapi2/fapi2.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#ifdef __RTOS_WIN32__
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        sprintf_s(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#else
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        snprintf(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#endif

#define LOG_ERROR(fmt, ...) \
    do {\
        printf("ERROR: "fmt"\n", ##__VA_ARGS__);\
    } while (0)

#define PRINT_TO_FILE(fmt, ...)\
    do {\
        LOG_MESSAGE(fmt, ##__VA_ARGS__);\
        if (OK != FMGMT_fprintf (pFile, fmt, ##__VA_ARGS__))\
        {\
            TPM2_DEBUG_PRINT("Failed to write to text file");\
            goto exit;\
        }\
    }while (0)

int main(int argc, char *argv[])
{
    int retval = -1;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pCtx = NULL;
    MgmtCapabilityIn getCapabilityIn = { 0 };
    MgmtCapabilityOut getCapabilityOut = { 0 };
    DIGICERT_initDigicert();

    rc = FAPI2_CONTEXT_init(&pCtx, sizeof("/dev/tpm0"), (ubyte*)"/dev/tpm0", 0, 10, NULL);
    //rc = FAPI2_CONTEXT_init(&pCtx, TPM_HW_VERSION_TPM12, sizeof("localhost"), (ubyte*)"localhost", 6543, 10);
    if (TSS2_RC_SUCCESS != rc)
    {
        printf("\nFailed to init FAPI context\n");
        goto exit;
    }

    getCapabilityIn.capability = TPM2_CAP_COMMANDS;
    getCapabilityIn.property = TPM2_CC_FIRST;
    getCapabilityIn.propertyCount = 255;
    rc = FAPI2_MGMT_getCapability(pCtx, &getCapabilityIn, &getCapabilityOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        printf("\nFailed to get capaibility\n");
        goto exit;
    }

    printf("Command Encrypt Decrypt:\n");
    for (int i = 0; i < getCapabilityOut.capabilityData.data.command.count; i++)
        printf("0x%x\n", getCapabilityOut.capabilityData.data.command.commandAttributes[i]);

    rc = TSS2_RC_SUCCESS;
    retval = 0;
exit:
    if (0 != retval || (TSS2_RC_SUCCESS != rc))
        LOG_ERROR("*****fapi2 capability failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}
