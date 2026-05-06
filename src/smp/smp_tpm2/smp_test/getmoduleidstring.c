/*
 * smp_tpm2_getidstring.c
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
 * @file       smp_tpm2_getidstring.c
 * @brief      Utility to return Module ID string from public key 
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
#include "../tpm2_lib/tpm2_types.h"
#include "../tpm2_lib/fapi2/fapi2.h"
#include "../../smp.h"
#include "../../smp_interface.h"
#include "../smp_tpm2_api.h"
#include "../smp_tap_tpm2.h"
#include "../smp_tpm2.h"
#include "../smp_tpm2_interface.h"

#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../common/mcmdline.h"
#include "tpm2_test_utils.h"
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#else
#include "../../../common/tpm2_path.h"
#endif

#define CONFIG_FILE_NAME_LEN        256


MOC_EXTERN_DATA_DECL TPM2_MODULE_CONFIG_SECTION *pgConfig;

MOC_EXTERN MSTATUS TPM2_parseConfiguration(TAP_Buffer *);
MOC_EXTERN MSTATUS TPM2_getDeviceModuleIdString(TPM2_MODULE_CONFIG_SECTION *pModuleInfo,
                ubyte *deviceModuleId);


#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define TPM2_DEBUG_PRINT_NO_ARGS(msg) \
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

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean configNameSpecified;
    char configName[CONFIG_FILE_NAME_LEN];
    int configNameLen;

    /* Set to only display mismatches between Configured and Device Module IDs */
    ubyte displayOnly;

    /* Set to update the configuration file with the correct device id string, in case of mismatch with Configured ID string */
    ubyte updateConfiguration;
} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("smp_tpm2_getidstr_bin: Help Menu\n");
    LOG_MESSAGE("Generate TPM2 secure element module id string for use in module configuration file");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [Display command line options]");
    LOG_MESSAGE("                   Help menu\n");
#ifdef __RTOS_WIN32__
    LOG_MESSAGE("           --c [Full configuration file name path (default to \%ProgramData\%\\Mocana\\tpm2.conf)]");
#else
    LOG_MESSAGE("           --c [Full configuration file name path (default to " TPM2_CONFIGURATION_FILE ")]");
#endif
    LOG_MESSAGE("                   Full configuration filename path\n");
    LOG_MESSAGE("           --d [Display mismatches]");
    LOG_MESSAGE("                   If there are any mismatches between the Configured and the Device ID string, using this option will display them.\n");
    LOG_MESSAGE("           --w [Update configuration file]");
    LOG_MESSAGE("                   If there are any mismatches between the Configured and the Device ID string, this option");
    LOG_MESSAGE("                   will update the input configuration file with device ID string\n");
    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
int parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    const struct option options[] = {
            {"h", no_argument, NULL, 1},
            {"c", required_argument, NULL, 2},
            {"d", no_argument, NULL, 3},
            {"w", no_argument, NULL, 4},
            {NULL, 0, NULL, 0},
    };

    if (!pOpts || !argv || (0 == argc))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameters.");
        goto exit;
    }

    while (TRUE)
    {
        c = getopt_long(argc, argv, optstring, options, &options_index);
        if ((-1 == c))
            break;

        switch (c)
        {
        case 1:
            printHelp();
            pOpts->exitAfterParse = TRUE;
            break;

        case 2:
            pOpts->configNameSpecified = TRUE;
            if (DIGI_STRLEN((const sbyte *)optarg) > CONFIG_FILE_NAME_LEN)
            {
                LOG_ERROR("Server name too long. Max size: %d bytes",
                        CONFIG_FILE_NAME_LEN);
                goto exit;
            }
            pOpts->configNameLen = DIGI_STRLEN((const sbyte *)optarg);
            if ((pOpts->configNameLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-c Config file name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->configName, optarg,
                    DIGI_STRLEN((const sbyte *)optarg)))
            {
                LOG_ERROR("Failed to copy memory");
                goto exit;
            }
            LOG_MESSAGE("TPM 2.0 configuration file: %s", pOpts->configName);
            break;

        case 3:
            pOpts->displayOnly = TRUE;
            break;

        case 4:
            pOpts->updateConfiguration = TRUE;
            break;

        default:
            goto exit;
            break;
        }
    }
    retval = 0;
exit:
    return retval;
}
#endif

static MSTATUS convertModuleIdStr(ubyte *pDeviceModuleId, 
                ubyte4 deviceModuleIdLen, ubyte *pDeviceModuleIdStr, 
                ubyte4 deviceModuleIdStrLen)
{
    MSTATUS status = OK;
    ubyte i = 0;

    if ((NULL == pDeviceModuleId) || (NULL == pDeviceModuleIdStr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (deviceModuleIdStrLen != (2*deviceModuleIdLen))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    while (i < deviceModuleIdLen)
    {
        /* Upper Nibble first */
        pDeviceModuleIdStr[i*2] = returnHexDigit((pDeviceModuleId[i] >> 4));
        /* Lower Nibble next */
        pDeviceModuleIdStr[(i*2)+1] = returnHexDigit(pDeviceModuleId[i]);
        
        i++;
    }

exit:
    return status;
}

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = OK;
    TAP_ConfigInfo configInfo = {0};
    int i = 0;
    ubyte deviceModuleId[SHA256_RESULT_SIZE];
    ubyte deviceModuleIdStr[SHA256_RESULT_SIZE*2]; /* Holds the ASCI string */
    ubyte mismatchFound = 0;
    sbyte4 cmpResult = 0;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfig = NULL;
    TPM2_MODULE_CONFIG_SECTION *pModuleInfo = NULL, *pNextModuleInfo = NULL;
    char *pConfigFile = NULL;
    
#ifdef __RTOS_WIN32__
    status = TPM2_TEST_UTILS_getTapWinConfigFilePath(&pConfigFile, "tpm2.conf");
    if (OK != status)
    {
        retval = -1;
        goto exit;
    }
#else
    pConfigFile = TPM2_CONFIGURATION_FILE;
#endif

    if (!pOpts)
    {
        LOG_ERROR("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

    /* Load TPM2 configuration file */
    if (pOpts->configNameSpecified)
        pConfigFile = pOpts->configName;

    status = DIGICERT_readFile(pConfigFile, &configInfo.configInfo.pBuffer,
            &configInfo.configInfo.bufferLen);
    if (OK != status)
    {
        LOG_ERROR("MOC_readFile failed with error %d", status);
        goto exit;
    }

    status = TPM2_parseConfiguration(&configInfo.configInfo);
    if (OK != status)
    {
        LOG_ERROR("TPM2_parseConfiguration failed with error %d", status);
        goto exit;
    }

    /* Validate all modules */
    pModuleConfig = pgConfig;
    while (pModuleConfig)
    {
        status = TPM2_getDeviceModuleIdString(pModuleConfig,
                deviceModuleId);

        if (OK != status)
        {
            LOG_ERROR("TPM2_getDeviceModuleIdString failed with error %d", status);
            goto exit;
        }

        /* Convert to string */
        status = convertModuleIdStr(deviceModuleId, 
                sizeof(deviceModuleId), deviceModuleIdStr, 
                sizeof(deviceModuleIdStr));
        if (OK != status)
        {
            LOG_ERROR("convertModuleIdStr failed with error %d", status);
            goto exit;
        }

        /* Compare with configured value */
        if (sizeof (deviceModuleIdStr) != pModuleConfig->configuredModuleIdStrLen)
        {
            LOG_MESSAGE("Device Module Id string length mismatch, device length %d does not match configured length %d\n",
                    (int)sizeof (deviceModuleIdStr),  pModuleConfig->configuredModuleIdStrLen);
        }
        else
        {
            cmpResult = 1;
            status = DIGI_MEMCMP(pModuleConfig->pConfiguredModuleIdStrStart,
                deviceModuleIdStr, sizeof(deviceModuleIdStr), &cmpResult);
            if (OK != status)
            {
                LOG_ERROR("Module comparison failed with error %d", status);
            }

            if (cmpResult)
            {
                mismatchFound++;

                if (pOpts->displayOnly || pOpts->updateConfiguration)
                {
                    LOG_MESSAGE("Module Configuration and Device ID string mismatch\n");
                    LOG_MESSAGE_NONL(    "Device Id string               : ");
                    for (i = 0; i < sizeof(deviceModuleIdStr); i++)
                    {
                        LOG_MESSAGE_NONL("%c", deviceModuleIdStr[i]);
                    }
                    LOG_MESSAGE_NONL("\n");
                    if (pOpts->displayOnly)
                        LOG_MESSAGE_NONL("Currently Configured Id string : ");
                    else
                        LOG_MESSAGE_NONL("Updated Id string              : ");
                    for (i = 0; i < pModuleConfig->configuredModuleIdStrLen; i++)
                    {
                        LOG_MESSAGE_NONL("%c", pModuleConfig->pConfiguredModuleIdStrStart[i]);
                    }
                    LOG_MESSAGE("\n");
                }

                if (pOpts->updateConfiguration)
                {
                    status = DIGI_MEMCPY(pModuleConfig->pConfiguredModuleIdStrStart, deviceModuleIdStr, sizeof(deviceModuleIdStr));
                    if (OK != status)
                    {
                        LOG_ERROR("Module id copy failed with error %d", status);
                    }
                }
            }
        }

        pModuleConfig = pModuleConfig->pNext;
    }

    if (mismatchFound)
    {
        LOG_MESSAGE("Mismatch between the Configured and the Device Module IDs found!\n");
    }
    else
    {
        LOG_MESSAGE("Configured and Device Module IDs match\n");
    }

    if (pOpts->updateConfiguration)
    {
        if (mismatchFound)
        {
            if (OK != (status = DIGICERT_writeFile(pConfigFile, configInfo.configInfo.pBuffer,
                            configInfo.configInfo.bufferLen)))
            {
                LOG_ERROR("Error %d updating configuration file %s\n",
                        status, pConfigFile);
            }
            else
                LOG_MESSAGE("Updated configuration file %s with Device ID string\n", pConfigFile);
        }
    }

    retval = 0;
exit:
    if (configInfo.configInfo.pBuffer)
        DIGICERT_freeReadFile(&configInfo.configInfo.pBuffer);

    pModuleInfo = pgConfig;

    while (pModuleInfo)
    {
        pNextModuleInfo = pModuleInfo->pNext;

        /* Free */
        if (pModuleInfo->moduleName.pBuffer)
        {
            DIGI_FREE((void **)&pModuleInfo->moduleName.pBuffer);
            pModuleInfo->moduleName.pBuffer = NULL;
            pModuleInfo->moduleName.bufferLen = 0;
        }
        if(pModuleInfo->credentialFile.pBuffer)
        {
            DIGI_FREE((void **)&pModuleInfo->credentialFile.pBuffer);
            pModuleInfo->credentialFile.pBuffer = NULL;
            pModuleInfo->credentialFile.bufferLen = 0;
        }

        DIGI_FREE((void **)&pModuleInfo);

        pModuleInfo = pNextModuleInfo;
    }
    pgConfig = NULL;

    return retval;
}

int main(int argc, char *argv[])
{
    int retval = -1;
    cmdLineOpts *pOpts = NULL;
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = parseCmdLineOpts;
#endif

    DIGICERT_initDigicert();

    if (NULL == platCmdLineParser)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts)))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    if (0 != platCmdLineParser(pOpts, argc, argv))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to parse command line options.");
        goto exit;
    }

    if (0 != executeOptions(pOpts))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Test execution Failed\n");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("***** Test execution failed *****");

    DIGICERT_freeDigicert();
    return retval;
}

