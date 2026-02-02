/*
 * moctpm2_takeownership.c
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
#include "../../../../common/base64.h"
#include "../../../../common/mfmgmt.h"
#include "../fapi2/fapi2.h"
#include "../../../../tap/tap_smp.h"
#include "../../smp_tpm2.h"
#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../../common/mcmdline.h"
#endif

/* Default DA Lockout parameters */
#define TPM2_DEFAULT_MAX_AUTHORIZATION_FAILURES    5
#define TPM2_DEFAULT_RECOVERY_TIME                 1000
#define TPM2_DEFAULT_LOCKOUT_RECOVERY_TIME         1000

#define MAX_AUTH_FAILURES                          256
#define MIN_AUTH_FAILURES                          3
/* Recovery times are in seconds */
#define MAX_RECOVERY_TIME                          7200
#define MAX_LOCKOUT_RECOVERY_TIME                  7200

#define SERVER_NAME_LEN 256
#define ERR_TAKEOWNERSHIP_ALREADY_DONE -2
#define ERR_PROVISIONING_ALREADY_DONE  -3

#define GET_NH_PWD          1 /* Get all new hierarchy passwords */
#define GET_OLH_PWD         2 /* Get old lockout hierarchy password */
#define GET_DA_PARAMETERS   3 /* Get DA parameters */

#define TPM2_DEBUG_PRINT_NO_ARGS(fmt) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TPM2_DEBUG_PRINT_1(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

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

extern MSTATUS
MocTap_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen,
      TAP_EntityCredentialList **pUsageCredentials) ;

extern MSTATUS MocSMP_PushCredentials(FileDescriptor pFile,TAP_EntityCredentialList* pEntityCredentials,
                        int numCredentials,byteBoolean provision);

extern  MSTATUS MocTap_FreeUsageCredentials(TAP_EntityCredentialList **pUsageCred);

typedef struct {
    byteBoolean exitAfterParse;
    byteBoolean forceClearOnly;
    byteBoolean ftpm;
    byteBoolean clearOnly;
    byteBoolean useSameAuthValue;
    byteBoolean oldLockoutAuthSupplied;
    byteBoolean ehOverride;
    byteBoolean shOverride;
    byteBoolean lhOverride;
    byteBoolean serverNameSpecified;
    byteBoolean credFileSupplied;
    byteBoolean credFileDisabled;
    /*
     * Endorsement hierarchy authValue override
     */
    TPM2B_AUTH newEhAuthValue;

    /*
     * Storage hierarchy authValue override
     */
    TPM2B_AUTH newShAuthValue;

    /*
     * Lockout hierarchy authValue override
     */
    TPM2B_AUTH newLhAuthValue;

    /*
     * Value to be used for all hierarchies.
     */
    TPM2B_AUTH all;

    /*
     * Current/old lockout auth required to clear the TPM
     */
    TPM2B_AUTH oldLockoutAuth;

    TPM2B_AUTH credFile;

    char serverName[SERVER_NAME_LEN];
    ubyte4 serverNameLen;
    ubyte4 serverPort;

    /* DA lockout parameters (optional, defaults are provided if atleast one parameter is specified) */
    byteBoolean daParameterSpecified;
    ubyte4 maxAuthFailures;
    ubyte4 recoveryTime;
    ubyte4 lockoutRecoveryTime;
} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("This tool takes ownership of a TPM 2.0 module. If the --c or --force "
            "option is specified, the TPM is cleared, otherwise ownership is taken."
            "Taking ownership requires setting the hierarchy passwords "
            "and optionally DA lockout parameters. "
            "The TPM is first cleared using the old lockout hierarchy password"
            " before the new values are set. --ftpm option should be specified for"
            " firmware TPM modules to create credentials file with well-known"
            " hierarchy passwords\n"
            );

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h");
    LOG_MESSAGE("                   Help menu.");
    LOG_MESSAGE("           --sm=[server name or module path]");
    LOG_MESSAGE("                   (Mandatory) Specify the Security Module; use localhost for the TPM\n"
                "                   emulator or module path for the hardware TPM (e.g. /dev/tpm0).");
    LOG_MESSAGE("           --ep=[server port]");
    LOG_MESSAGE("                   Specify the port number for the TPM emulator (applicable only for --sm=localhost).");
    LOG_MESSAGE("           --ehpwd=[password]");
    LOG_MESSAGE("                   Specify the new Endorsement Hierarchy password. If no password is specified, the\n"
                "                   well-known password is used. Password must be provided with quotes.");
    LOG_MESSAGE("           --shpwd=[password]");
    LOG_MESSAGE("                   Specify the new Storage Hierarchy password. If no password is specified, the\n"
                "                   well-known password is used. Password must be provided with quotes.");
    LOG_MESSAGE("           --olhpwd=[password]");
    LOG_MESSAGE("                   Specify the old Lockout Hierarchy password. This is needed for taking ownership of a configured\n"
                "                   TPM device. Password must be provided with quotes.");
    LOG_MESSAGE("           --lhpwd=[password]");
    LOG_MESSAGE("                   Specify the new Lockout Hierarchy password. If no password is specified, the\n"
                "                   well-known password is used. Password must be provided with quotes.");
    LOG_MESSAGE("           --authfail=[count]");
    LOG_MESSAGE("                   [Optional] Specify the number of authorization failures before lockout is imposed. (Range 3-256, Default 5)"); 
    LOG_MESSAGE("           --rcytime=[seconds]");
    LOG_MESSAGE("                   [Optional] Specify the time in seconds before the count of authorization failures is automatically decremented\n" 
                "                   A value of zero indicates that DA protection is disabled. Default value is 1000 secs.");
    LOG_MESSAGE("           --lorcy=[seconds]");
    LOG_MESSAGE("                   [Optional] Specify the time in seconds after a lockout authentication failure before use of lockout authentication is allowed\n" 
                "                   A value of zero indicates that a reboot is required. Default value is 1000 secs.");
    LOG_MESSAGE("           --c");
    LOG_MESSAGE("                   Clears the TPM without setting hierarchy passwords.");
    LOG_MESSAGE("           --force");
    LOG_MESSAGE("                   Clears the TPM including all hierarchy passwords using the default Platform Hierarchy password."); 
    LOG_MESSAGE("           --ftpm");
    LOG_MESSAGE("                   (Optional) Indicates a firmware based TPM (e.g Intel FTPM) wherein the TPM ownership is taken by the system with \n"
                "                   well-known passwords for the Lockout, Storage and Endorsement hierarchies. The credential file is generated \n"
                "                   for use with digicert_tpm2_provision command.");
    LOG_MESSAGE("           --nocredfile");
    LOG_MESSAGE("                   Disables generation and use of the credentials file. The required credentials must be\n"
                "                   specified as command line arguments or environment variables.");
    LOG_MESSAGE("           --credfile=[credentials file]");
    LOG_MESSAGE("                   Credentials file that comprises of encoded passwords required to use the TPM.\n");

    return;
}

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
static int parseCmdLineOpts(cmdLineOpts *pOpts, int argc, char *argv[])
{
    int retval = -1;
    int c = 0;
    int options_index = 0;
    const char *optstring = "";
    const struct option options[] = {
            {"h", no_argument, NULL, 1},
            {"c", no_argument, NULL, 2},
            {"ep", required_argument, NULL, 3},
            {"sm", required_argument, NULL, 5},
            {"ehpwd", required_argument, NULL, 6},
            {"shpwd", required_argument, NULL, 7},
            {"lhpwd", required_argument, NULL, 8},
            {"olhpwd", required_argument, NULL, 9},
            {"credfile", required_argument, NULL, 10},
            {"nocredfile", no_argument, NULL, 11},
            {"authfail", required_argument, NULL, 12},
            {"rcytime", required_argument, NULL, 13},
            {"lorcy", required_argument, NULL, 14},
            {"force", no_argument, NULL, 15},
            {"ftpm", no_argument, NULL, 16},
            {NULL, 0, NULL, 0},
    };

    if (!pOpts || !argv || (0 == argc))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameters.");
        goto exit;
    }

    pOpts->maxAuthFailures = TPM2_DEFAULT_MAX_AUTHORIZATION_FAILURES;
    pOpts->recoveryTime = TPM2_DEFAULT_RECOVERY_TIME;
    pOpts->lockoutRecoveryTime = TPM2_DEFAULT_LOCKOUT_RECOVERY_TIME;

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
                TPM2_DEBUG_PRINT_NO_ARGS("TPM2 Clear requested");
                pOpts->clearOnly = TRUE;
                break;
            case 3:
                if (('\0' == optarg[0]) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Invalid port number specified");
                    goto exit;
                }
                pOpts->serverPort = strtoul(optarg, NULL, 0);
                if ((pOpts->serverPort < 1) || (pOpts->serverPort > 65535))
                {
                    LOG_ERROR("Invalid port number. Must be 1-65535");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Server Port: %u", pOpts->serverPort);
                break;
            case 5:
                pOpts->serverNameSpecified = TRUE;
                pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->serverNameLen >= SERVER_NAME_LEN)
                {
                    LOG_ERROR("Server name too long. Max size: %d bytes",
                            SERVER_NAME_LEN - 1);
                    goto exit;
                }
                if ((pOpts->serverNameLen == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--sm security module name not specified");
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg, pOpts->serverNameLen))
                {
                    TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                    goto exit;
                }
                pOpts->serverName[pOpts->serverNameLen] = '\0';
                TPM2_DEBUG_PRINT("TPM2 Security Module name: %s", pOpts->serverName);
                break;
            case 6:
                pOpts->ehOverride = TRUE;

                pOpts->newEhAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->newEhAuthValue.size > sizeof(pOpts->newEhAuthValue.buffer))
                {
                    LOG_ERROR("--ehpwd Password Length too long. Max size: %u bytes",
                            (unsigned int)sizeof(pOpts->newEhAuthValue.buffer));
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->newEhAuthValue.buffer, optarg, pOpts->newEhAuthValue.size))
                {
                    TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                    goto exit;
                }
                pOpts->newEhAuthValue.buffer[pOpts->newEhAuthValue.size] = '\0';
                TPM2_DEBUG_PRINT("New endorsement password: %s", pOpts->newEhAuthValue.buffer);

                break;
            case 7:
                pOpts->shOverride = TRUE;

                pOpts->newShAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->newShAuthValue.size > sizeof(pOpts->newShAuthValue.buffer))
                {
                    LOG_ERROR("--shpwd Password Length too long. Max size: %u bytes",
                            (unsigned int)sizeof(pOpts->newShAuthValue.buffer));
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->newShAuthValue.buffer, optarg, pOpts->newShAuthValue.size))
                {
                    TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                    goto exit;
                }
                pOpts->newShAuthValue.buffer[pOpts->newShAuthValue.size] = '\0';
                TPM2_DEBUG_PRINT("New storage password: %s", pOpts->newShAuthValue.buffer);

                break;
            case 8:
                pOpts->lhOverride = TRUE;

                pOpts->newLhAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->newLhAuthValue.size > sizeof(pOpts->newLhAuthValue.buffer))
                {
                    LOG_ERROR("--lhpwd Password Length too long. Max size: %u bytes",
                            (unsigned int)sizeof(pOpts->newLhAuthValue.buffer));
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->newLhAuthValue.buffer, optarg, pOpts->newLhAuthValue.size))
                {
                    TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                    goto exit;
                }
                pOpts->newLhAuthValue.buffer[pOpts->newLhAuthValue.size] = '\0';
                TPM2_DEBUG_PRINT("New lockout password: %s", pOpts->newLhAuthValue.buffer);

                break;
            case 9:
                pOpts->oldLockoutAuthSupplied = TRUE;
                /*
                 * old lockout auth can be the EmptyBuffer. so -olh with nothing following
                 * it implies EmptyBuffer.
                 */

                pOpts->oldLockoutAuth.size = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->oldLockoutAuth.size > sizeof(pOpts->oldLockoutAuth.buffer))
                {
                    LOG_ERROR("--olhpwd Password Length too long. Max size: %u bytes",
                            (unsigned int)sizeof(pOpts->oldLockoutAuth.buffer));
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->oldLockoutAuth.buffer, optarg, pOpts->oldLockoutAuth.size))
                {
                    TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                    goto exit;
                }
                pOpts->oldLockoutAuth.buffer[pOpts->oldLockoutAuth.size] = '\0';
                TPM2_DEBUG_PRINT("Old lockout password: %s", pOpts->oldLockoutAuth.buffer);

                break;
            case 10:
                if (TRUE == pOpts->credFileDisabled)
                {
                    LOG_ERROR("--nocredfile cannot be specified alongwith --credfile option");
                    pOpts->exitAfterParse = TRUE;
                    goto exit;
                }
                pOpts->credFileSupplied = TRUE;

                pOpts->credFile.size = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->credFile.size > sizeof(pOpts->credFile.buffer))
                {
                    LOG_ERROR("--credfile file Length too long. Max size: %u bytes",
                            (unsigned int)sizeof(pOpts->credFile.buffer));
                    goto exit;
                }
                if ((pOpts->credFile.size == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--credfile value starts with invalid character.");
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->credFile.buffer, optarg, pOpts->credFile.size))
                {
                    TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                    goto exit;
                }
                pOpts->credFile.buffer[pOpts->credFile.size] = '\0';
                TPM2_DEBUG_PRINT("Cred File name: %s", pOpts->credFile.buffer);

                break;

            case 11:
                if (TRUE == pOpts->credFileSupplied)
                {
                    LOG_ERROR("--credfile cannot be specified with --nocredfile option");
                    pOpts->exitAfterParse = TRUE;
                    goto exit;
                }
                pOpts->credFileDisabled = TRUE;

                TPM2_DEBUG_PRINT_1("Credentials file option disabled\n");
                break;

            case 12:
                if (('\0' == optarg[0]) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Invalid authorization failures count");
                    goto exit;
                }
                pOpts->maxAuthFailures = strtoul(optarg, NULL, 0);
                if ((pOpts->maxAuthFailures < MIN_AUTH_FAILURES) || 
                        (pOpts->maxAuthFailures > MAX_AUTH_FAILURES))
                {
                    LOG_ERROR("Authorization failures count must be between %u and %u",
                            MIN_AUTH_FAILURES, MAX_AUTH_FAILURES);
                    goto exit;
                }
                pOpts->daParameterSpecified = TRUE;
                TPM2_DEBUG_PRINT("max Authorization Failures: %u\n", 
                        pOpts->maxAuthFailures);

                break;

            case 13:
                if ((NULL == optarg) || ('\0' == optarg[0]) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Invalid recovery time value");
                    goto exit;
                }
                pOpts->daParameterSpecified = TRUE;
                pOpts->recoveryTime = strtoul(optarg, NULL, 0);
                if (pOpts->recoveryTime)
                {
                    if (MAX_RECOVERY_TIME < pOpts->recoveryTime)
                    {
                        LOG_ERROR("Max recovery time must be less than %u secs",
                                MAX_RECOVERY_TIME);
                        goto exit;
                    }
                    TPM2_DEBUG_PRINT("Recovery time: %u secs\n",
                        pOpts->recoveryTime);
                }
                else
                    TPM2_DEBUG_PRINT_1("DA protection disabled\n");

                break;

            case 14:
                if ((NULL == optarg) || ('\0' == optarg[0]) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Invalid lockout recovery time value");
                    goto exit;
                }
                pOpts->daParameterSpecified = TRUE;
                pOpts->lockoutRecoveryTime = strtoul(optarg, NULL, 0);
                if (pOpts->lockoutRecoveryTime)
                {
                    if (MAX_LOCKOUT_RECOVERY_TIME < pOpts->lockoutRecoveryTime)
                    {
                        LOG_ERROR("Max lockout recovery time must be less than %u secs",
                                MAX_LOCKOUT_RECOVERY_TIME);
                        goto exit;
                    }
                    TPM2_DEBUG_PRINT("Lockout Recovery time: %u secs\n", 
                        pOpts->lockoutRecoveryTime);
                }
                else
                    TPM2_DEBUG_PRINT_1("Reboot required for Lockout Recovery\n");

                break;

            case 15:
                TPM2_DEBUG_PRINT_NO_ARGS("TPM2 Force clear requested");
                pOpts->forceClearOnly = TRUE;
                break;

            case 16:
                TPM2_DEBUG_PRINT_NO_ARGS("TPM2 firmware TPM configuration");
                pOpts->ftpm = TRUE;
                break;

            default:
                pOpts->exitAfterParse = TRUE;
                goto exit;
                break;
        }
    }
    retval = 0;
exit:
    return retval;
}
#endif

int clearCredentialsFile(cmdLineOpts *pOpts)
{
    int rc = -1;
    int numCredentials = 0;
    TAP_EntityCredentialList entityCredentials = { 0 } ;
    int i = 0;
    MSTATUS status = OK;
    ubyte *pBase64Value = NULL;
    ubyte4 base64ValueLen = 0;
    ubyte *pRawFileBuffer = NULL;
    ubyte4 rawFileBufferLen = 0;
    FileDescriptor pFile = NULL;

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameter.");
        goto exit;
    }

    status = FMGMT_fopen (pOpts->credFile.buffer,"w", &pFile);
    if (OK != status)
    {   
        LOG_ERROR("Failed to open credential file");
        goto exit;
    }
    
    if(TRUE == pOpts->credFileSupplied)
    {
        numCredentials = 1;
 
        if (0 < numCredentials)
        {
            status = DIGI_CALLOC((void **) &(entityCredentials.pEntityCredentials), numCredentials, sizeof(TAP_EntityCredential));

            if (OK != status)
            {
                LOG_ERROR("Failed to allocate memory; status %d", status);
                goto exit;
            }
            i = 0;

            {
                status = DIGI_CALLOC((void **) &(entityCredentials.pEntityCredentials[i].credentialList.pCredentialList), 1,
                                sizeof(TAP_Credential));
                if (OK != status)
                {
                    LOG_ERROR("Failed to allocate memory; status %d", status);
                    goto exit;
                }
                entityCredentials.pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_UNKNOWN;
                entityCredentials.pEntityCredentials[i].parentId = 0;
                entityCredentials.pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_MODULE;
                entityCredentials.pEntityCredentials[i].entityId = TPM2_RH_LOCKOUT_ID;

                entityCredentials.pEntityCredentials[i].credentialList.numCredentials = 1;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = 1;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = 1;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = 3;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = 0; 
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = (ubyte *)""; 
                i++;
            }
        }
    }
    entityCredentials.numCredentials  = numCredentials;
    status = MocSMP_PushCredentials(pFile, &entityCredentials,numCredentials,FALSE);

    if(OK != status)
    {
        LOG_ERROR("Failed to process configuration file; status %d", status);
        goto exit;
    }        

    if (NULL != pFile)
    {
        FMGMT_fclose (&pFile);

        /* Base64 encode credentials file */
        status = DIGICERT_readFile((const char *)pOpts->credFile.buffer,
                &pRawFileBuffer, &rawFileBufferLen);
        if (OK == status)
        {
            /* Convert to Base64 */
            status = BASE64_encodeMessage(pRawFileBuffer, rawFileBufferLen,
                    &pBase64Value, &base64ValueLen);
            if (OK == status)
            {
                DIGICERT_writeFile((const char *)pOpts->credFile.buffer, pBase64Value, base64ValueLen);
                LOG_MESSAGE("Credentials file encoded");
            }

            DIGICERT_freeReadFile(&pRawFileBuffer);
        }
    }

    rc = 0;
exit:

    if (NULL != pBase64Value)
        DIGI_FREE((void **)&pBase64Value);

    if (entityCredentials.pEntityCredentials)
    {   
        for (i = 0; i < numCredentials; i++)
        {
            if (entityCredentials.pEntityCredentials[i].credentialList.pCredentialList)
                DIGI_FREE((void **)&entityCredentials.pEntityCredentials[i].credentialList.pCredentialList);
        }

        DIGI_FREE((void **)&entityCredentials.pEntityCredentials);
    }

    if (NULL != pFile)
    {
        FMGMT_fclose(&pFile);
    }

    return rc;
}

int clearTpm(cmdLineOpts *pOpts, FAPI2_CONTEXT *pCtx)
{
    int retval = -1;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ContextSetHierarchyAuthIn hierarchyAuths = { 0 };
    ubyte *pRawBuffer = NULL;
    ubyte4 rawBufferLen = 0;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Buffer userCredBuf = {0} ;
    MSTATUS status= OK;
    int numCredentials = 0,ch;
    FileDescriptor pFile;

    if (!pOpts || !pCtx)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameter.");
        goto exit;
    }

    if (FALSE == pOpts->forceClearOnly)
    {
        if(pOpts->credFileSupplied)
        {
            status = FMGMT_fopen (pOpts->credFile.buffer,"r", &pFile);
            if(OK == status)
            {
                ch = FMGMT_fgetc (pFile);
                if(ch == MOC_EOF)
                {
                    LOG_ERROR("Configuration file is empty. Setting Lockout password to default\n");
                    FMGMT_fclose (&pFile);
                    goto set;
                }
                else
                {
                    FMGMT_fclose (&pFile);

                    status = DIGICERT_readFile((const char*)pOpts->credFile.buffer, &(pRawBuffer),
                            (ubyte4 *)&(rawBufferLen));
                    if (OK != status)
                    {
                        LOG_ERROR("Failed to read user credential file %s, status = %d",
                                pOpts->credFile.buffer, status);
                        goto exit;
                    }

                    status =  BASE64_decodeMessage(pRawBuffer,rawBufferLen, &userCredBuf.pBuffer, &userCredBuf.bufferLen);
                    if (OK != status)
                    {
                        LOG_ERROR("Failed to decode credential file %s, status = %d",
                                pOpts->credFile.buffer, status);
                        goto exit;
                    } 
                    status = MocTap_GetCredentialData(( sbyte *)userCredBuf.pBuffer, userCredBuf.bufferLen,
                            &pEntityCredentials) ;
                    if (OK != status)
                    {
                        LOG_ERROR("Failed to get user credential data from file %s, status = %d",
                                pOpts->credFile.buffer,  status);
                        goto exit;
                    }

                    numCredentials = pEntityCredentials->numCredentials;

                    while(numCredentials > 0)
                    {
                        if( (pEntityCredentials->pEntityCredentials[numCredentials -1].entityId) == TPM2_RH_LOCKOUT_ID)
                        {
                            pOpts->oldLockoutAuth.size = pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.bufferLen;
                            DIGI_MEMCPY(pOpts->oldLockoutAuth.buffer,pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.pBuffer,pOpts->oldLockoutAuth.size);
                            break;
                        }
                        numCredentials = numCredentials -1;
                    }
                }
            }
        }
        else if (pOpts->credFileDisabled)
        {
        }
        else
        {
            LOG_ERROR("--credfile or --nocredfile option must be specified");
            goto exit;
        }
    }
set:
    if (FALSE == pOpts->forceClearOnly)
    {
        hierarchyAuths.lockoutAuth = pOpts->oldLockoutAuth;
        hierarchyAuths.forceUseLockoutAuth = TRUE;
        rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &hierarchyAuths);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to set hierarchy auths in FAPI2 context");
            goto exit;
        }
    }

    if (FALSE == pOpts->forceClearOnly)
    {
        rc = FAPI2_ADMIN_releaseOwnership(pCtx);
        if (TSS2_RC_SUCCESS != rc)
        {
            LOG_ERROR("Failed to clear TPM. rc = 0x%02x",  (unsigned int)rc);
            goto exit;
        }
    }
    else
    {
        rc = FAPI2_ADMIN_forceClear(pCtx);
        if (TSS2_RC_SUCCESS != rc)
        {
            LOG_ERROR("Failed to force clear TPM. rc = 0x%02x",  (unsigned int)rc);
            goto exit;
        }
    }
    retval = 0;

    if (FALSE == pOpts->forceClearOnly)
    {
        if (pOpts->credFileSupplied)
            clearCredentialsFile(pOpts);
    }
exit:
    if(NULL != pRawBuffer)
        DIGICERT_freeReadFile(&pRawBuffer);

    if(NULL != pEntityCredentials)
        MocTap_FreeUsageCredentials(&pEntityCredentials) ;

    if(NULL != userCredBuf.pBuffer)
        DIGI_FREE((void**)&(userCredBuf.pBuffer));

    if (TSS2_RC_SUCCESS != rc)
        retval = -1;
    return retval;
}

int takeOwnership(cmdLineOpts *pOpts, FAPI2_CONTEXT *pCtx)
{
    int retval = -1;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ContextSetHierarchyAuthIn hierarchyAuths = { 0 };
    AdminTakeOwnershipIn takeOwnershipIn = { 0 };

    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Buffer userCredBuf = {0} ;
    MSTATUS status= OK;
    ubyte *pRawBuffer = NULL;
    ubyte4 rawBufferLen = 0;
    int numCredentials = 0,ch;
    FileDescriptor pFile;

    if (!pOpts || !pCtx)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameter.");
        goto exit;
    }

    if(pOpts->credFileSupplied)
    {
        status = FMGMT_fopen (pOpts->credFile.buffer,"r", &pFile);
        if (OK == status)
        {
            ch = FMGMT_fgetc (pFile);
            if(ch== MOC_EOF)
            {
                LOG_ERROR("Configuration file is empty. Setting Lockout password to default\n");
                FMGMT_fclose (&pFile);
                goto set;
            }
            else
            {
                FMGMT_fclose (&pFile);

                status = DIGICERT_readFile((const char*)pOpts->credFile.buffer, &(pRawBuffer),
                             (ubyte4 *)&(rawBufferLen));
                if (OK != status)
                {
                    LOG_ERROR("Failed to read user credential file %s, status = %d",
                        pOpts->credFile.buffer, status);
                    goto exit;
                }
                status =  BASE64_decodeMessage(pRawBuffer,rawBufferLen, &userCredBuf.pBuffer, &userCredBuf.bufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Failed to decode credential file %s, status = %d",
                        pOpts->credFile.buffer, status);
                    goto exit;
                }
                status = MocTap_GetCredentialData(( sbyte *)userCredBuf.pBuffer, userCredBuf.bufferLen,
                    &pEntityCredentials) ;
                if (OK != status)
                {
                    LOG_ERROR("Failed to get user credential data from file %s, status = %d",
                        pOpts->credFile.buffer,  status);
                    goto exit;
                }

                numCredentials = pEntityCredentials->numCredentials;

                if (3 == numCredentials)
                {
                    rc = TSS2_RC_SUCCESS; 
                    retval = ERR_TAKEOWNERSHIP_ALREADY_DONE;
                    LOG_MESSAGE("TPM ownership has already been taken. Use the digicert_tpm2_provision command to provision the TPM.\n");
                    goto exit;
                }
                else if (5 == numCredentials)
                {
                    rc = TSS2_RC_SUCCESS; 
                    retval = ERR_PROVISIONING_ALREADY_DONE;
                    LOG_MESSAGE("The TPM has already been provisioned. You must clear the TPM to retake ownership\n");
                    goto exit;
                }

                while(numCredentials > 0)
                {
                    switch(pEntityCredentials->pEntityCredentials[numCredentials -1].entityId)
                    {
                        case TPM2_RH_LOCKOUT_ID:

                            takeOwnershipIn.newLockOutAuth.size = 
                                pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.bufferLen;
                            DIGI_MEMCPY(takeOwnershipIn.newLockOutAuth.buffer,
                                    pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.pBuffer,
                                    takeOwnershipIn.newLockOutAuth.size);
                            break;

                        case TPM2_RH_ENDORSEMENT_ID:
                            takeOwnershipIn.newEndorsementAuth.size = 
                                pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.bufferLen;
                            DIGI_MEMCPY(takeOwnershipIn.newEndorsementAuth.buffer,
                                    pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.pBuffer,
                                    takeOwnershipIn.newEndorsementAuth.size);
                            break;

                        case TPM2_RH_OWNER_ID:
                            takeOwnershipIn.newOwnerAuth.size = 
                                pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.bufferLen;
                            DIGI_MEMCPY(takeOwnershipIn.newOwnerAuth.buffer,
                                    pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.pBuffer, 
                                    takeOwnershipIn.newOwnerAuth.size); 
                            break;
                    }
                    numCredentials = numCredentials -1;
                }
            }
        }
    }
    else if (pOpts->credFileDisabled)
    {
        if (FALSE == pOpts->oldLockoutAuthSupplied)
        {
            LOG_ERROR("--olh option must be used to specify the old lockout hierarchy password");
            goto exit;
        }
    }
    else
    {
        LOG_ERROR("--credfile or --nocredfile option must be specified");
        goto exit;
    }

set:
    hierarchyAuths.lockoutAuth = pOpts->oldLockoutAuth;
    hierarchyAuths.forceUseLockoutAuth = TRUE;
    rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &hierarchyAuths);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to set hierarchy auths in FAPI2 context");
        goto exit;
    }

    if (pOpts->ehOverride)
        takeOwnershipIn.newEndorsementAuth = pOpts->newEhAuthValue;
    else
        takeOwnershipIn.newEndorsementAuth = pOpts->all;

    if (pOpts->shOverride)
        takeOwnershipIn.newOwnerAuth = pOpts->newShAuthValue;
    else
        takeOwnershipIn.newOwnerAuth = pOpts->all;

    if (pOpts->lhOverride)
        takeOwnershipIn.newLockOutAuth = pOpts->newLhAuthValue;
    else
        takeOwnershipIn.newLockOutAuth = pOpts->all;

    rc = FAPI2_ADMIN_takeOwnership(pCtx, &takeOwnershipIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Unable to take TPM ownership. rc = 0x%02x",  (unsigned int)rc);
        goto exit;
    }

    retval = 0;
exit:
    if(NULL!= pEntityCredentials)
        MocTap_FreeUsageCredentials(&pEntityCredentials);

    if(NULL != pRawBuffer)
        DIGICERT_freeReadFile(&pRawBuffer);

    if(NULL != userCredBuf.pBuffer)
        DIGI_FREE((void**)&(userCredBuf.pBuffer));
    if (TSS2_RC_SUCCESS != rc)
        retval = -1;
    return retval;
}

/*------------------------------------------------------------------*/

MSTATUS getCredentialsFromEnvironment(cmdLineOpts *pOpts, int pwdType)
{
    MSTATUS status = ERR_INVALID_ARG;

    if (NULL == pOpts)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((GET_NH_PWD != pwdType) &&
            (GET_OLH_PWD != pwdType) && (GET_DA_PARAMETERS != pwdType))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (GET_OLH_PWD == pwdType)
    {
        char *pEnv = NULL;
        int envLen = 0;

        /* Old lockout password */
        pEnv = getenv("DIGICERT_TPM2_OLD_LOCKOUT_PASSWORD");
        if (pEnv)
        {
            envLen = DIGI_STRLEN((const sbyte *)pEnv);
            if (envLen >= sizeof(pOpts->oldLockoutAuth.buffer))
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            DIGI_MEMCPY(pOpts->oldLockoutAuth.buffer, pEnv, envLen);
            pOpts->oldLockoutAuth.size = envLen;
            pOpts->oldLockoutAuth.buffer[envLen] = '\0';
            pOpts->oldLockoutAuthSupplied = TRUE;
            status = OK;
        }
    }
    else if (GET_DA_PARAMETERS == pwdType)
    {
        char *pEnv = NULL;

        pEnv = getenv("DIGICERT_TPM2_DA_MAX_AUTH_FAILURES");
        if (pEnv)
        {
            pOpts->maxAuthFailures = (ubyte4)DIGI_ATOL((const sbyte *)pEnv, NULL);
            if ((pOpts->maxAuthFailures < MIN_AUTH_FAILURES) || 
                    (pOpts->maxAuthFailures > MAX_AUTH_FAILURES))
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }

            pOpts->daParameterSpecified = TRUE;
        }

        pEnv = getenv("DIGICERT_TPM2_DA_RECOVERY_TIME");
        if (pEnv)
        {
            pOpts->recoveryTime = (ubyte4)DIGI_ATOL((const sbyte *)pEnv, NULL);
            if (MAX_RECOVERY_TIME < pOpts->recoveryTime)
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }

            pOpts->daParameterSpecified = TRUE;
        }

        pEnv = getenv("DIGICERT_TPM2_DA_LOCKOUT_RECOVERY");
        if (pEnv)
        {
            pOpts->lockoutRecoveryTime = (ubyte4)DIGI_ATOL((const sbyte *)pEnv, NULL);
            if (MAX_LOCKOUT_RECOVERY_TIME < pOpts->lockoutRecoveryTime)
            {
                status = ERR_INVALID_ARG;
                goto exit;
            }

            pOpts->daParameterSpecified = TRUE;
        }

        status = OK;
    }
    else
    {
        char *pEnv = NULL;
        int envLen = 0;
#ifdef MOCANA_ALLOW_SAME_PWD
        pEnv = getenv("DIGICERT_TPM2_ALL_HIERARCHIES_PASSWORD");
        if (pEnv)
        {
            envLen = DIGI_STRLEN((const sbyte *)pEnv);
            if (envLen >= sizeof(pOpts->all.buffer))
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            DIGI_MEMCPY(pOpts->all.buffer, pEnv, envLen);
            pOpts->all.size = envLen;
            pOpts->all.buffer[envLen] = '\0';
            pOpts->useSameAuthValue = TRUE;
            status = OK;
        }

        if (FALSE == pOpts->useSameAuthValue)
#endif
        {
            pEnv = getenv("DIGICERT_TPM2_LOCKOUT_HIERARCHY_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->newLhAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->newLhAuthValue.buffer, pEnv, envLen);
                pOpts->newLhAuthValue.size = envLen;
                pOpts->newLhAuthValue.buffer[envLen] = '\0';
                pOpts->lhOverride = TRUE;
            }

            pEnv = getenv("DIGICERT_TPM2_ENDORSEMENT_HIERARCHY_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->newEhAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->newEhAuthValue.buffer, pEnv, envLen);
                pOpts->newEhAuthValue.size = envLen;
                pOpts->newEhAuthValue.buffer[envLen] = '\0';
                pOpts->ehOverride = TRUE;
            }

            pEnv = getenv("DIGICERT_TPM2_STORAGE_HIERARCHY_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->newShAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->newShAuthValue.buffer, pEnv, envLen);
                pOpts->newShAuthValue.size = envLen;
                pOpts->newShAuthValue.buffer[envLen] = '\0';
                pOpts->shOverride = TRUE;
            }

            status = OK;
        }
    }

exit:
    return status;
}


int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pCtx = NULL;
    ContextGetAuthValueLengthOut maxAuthValueLen = { 0 };
    TAP_EntityCredentialList entityCredentials = { 0 } ;
    ContextSetHierarchyAuthIn hierarchyAuths = { 0 };
    MSTATUS status;
    int numCredentials = 0;
    int i = 0;
    FileDescriptor pFile =NULL;
    int initFlag = 0;
    ubyte *pBase64Value = NULL;
    ubyte4 base64ValueLen = 0;
    ubyte *pRawFileBuffer = NULL;
    ubyte4 rawFileBufferLen = 0;

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }

    if (!pOpts->serverNameSpecified)
    {
        LOG_ERROR("--sm must be specified. Server/Module name is required.");
        goto exit;
    }

    if (TRUE == pOpts->ftpm)
    {
        if (FALSE == pOpts->credFileSupplied)
        {
            LOG_ERROR("--credfile option must be specified");
            goto exit;
        }

        if (TRUE == pOpts->credFileDisabled)
        {
            LOG_ERROR("--nocredfile option cannot be used with firmware TPM");
            goto exit;
        }

        if (TRUE == pOpts->forceClearOnly)
        {
            LOG_ERROR("--force option cannot be used with firmware TPM");
            goto exit;
        }

        if (TRUE == pOpts->clearOnly)
        {
            LOG_ERROR("--c option cannot be used with firmware TPM");
            goto exit;
        }
    }

    if (FALSE == pOpts->forceClearOnly)
    {
        if(!pOpts->credFileSupplied && !pOpts->credFileDisabled)
        {
            LOG_ERROR("One of --nocredfile or --credfile options must be specified");
            goto exit;
        }
    }

    /* If we are operating without credentials file, and credentials are not provided over
       command line argument, check if Environment variables have been configured */
    if (pOpts->credFileDisabled)
    {
        if (FALSE == pOpts->forceClearOnly)
        {
            if (FALSE == pOpts->oldLockoutAuthSupplied)
            {
                if (OK != getCredentialsFromEnvironment(pOpts, GET_OLH_PWD))
                {
                    if (TRUE == pOpts->credFileDisabled)
                        LOG_ERROR("Environment option MOCANA_TPM2_OLD_LOCKOUT_PASSWORD must be used to specify the old lockout hierarchy password");
                    else
                        LOG_ERROR("--olh option must be used to specify the old lockout hierarchy password");
                    goto exit;
                }
            }
        }
    }

    /* If command line parameters not available, check exported environment variables */
    if ((FALSE == pOpts->forceClearOnly) && (FALSE == pOpts->ftpm))
    {
        if (FALSE == pOpts->daParameterSpecified)
        {
            if (OK != getCredentialsFromEnvironment(pOpts, GET_DA_PARAMETERS))
            {
                LOG_ERROR("Error reading DA parameters from environment variables\n");
            }
        }
    }

    /*
     * old lockout password always has to be supplied.
     */
    /*    if (!pOpts->oldLockoutAuthSupplied)
          {
          LOG_ERROR("--olh must be specified. Old lockout hierarchy password is required to take ownership.");
          goto exit;
          }*/

    initFlag = 1;
    rc = FAPI2_CONTEXT_init(&pCtx, pOpts->serverNameLen,
            (ubyte *)pOpts->serverName, pOpts->serverPort, 3, &initFlag);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to create FAPI2 context.");
        goto exit;
    }

    if (TRUE == pOpts->forceClearOnly)
    {
        LOG_MESSAGE("Force clearing TPM...");
        retval = clearTpm(pOpts, pCtx);
        if (0 == retval)
            LOG_MESSAGE("Force cleared TPM successfully.");
        goto exit;
    }

    rc = FAPI2_CONTEXT_getMaxAuthValueLength(pCtx, &maxAuthValueLen);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Could not get maximum authValue lengths");
        goto exit;
    }

    if (pOpts->oldLockoutAuth.size > maxAuthValueLen.hierarchyAuthValueLen)
    {
        LOG_ERROR("Old lockout password length greater than supported size. "
                "Password length: %d, max: %d", pOpts->oldLockoutAuth.size,
                maxAuthValueLen.hierarchyAuthValueLen);
        goto exit;
    }

    /*
     * If clear is requested, ignore all other options.
     */
    if (pOpts->clearOnly)
    {
        LOG_MESSAGE("Clearing TPM...");
        retval = clearTpm(pOpts, pCtx);
        if (0 == retval)
            LOG_MESSAGE("Cleared TPM successfully.");
        goto exit;
    }

    /*
     * For taking ownership, either -a has to be provided, or the rest of
     * -ehpwd, -shpwd, -lhpwd must be provided.
     */
    if (!pOpts->useSameAuthValue && (FALSE == pOpts->ftpm))
    {
        if (!pOpts->ehOverride || !pOpts->shOverride || !pOpts->lhOverride)
        {
            if (pOpts->credFileDisabled)
            {
                /* Check if these credentials are available in the environment variables */
                if (OK != getCredentialsFromEnvironment(pOpts, GET_NH_PWD))
                {
                    if (!pOpts->useSameAuthValue)
                    {
                        if (!pOpts->lhOverride)
                            LOG_ERROR("Environment variable MOCANA_TPM2_LOCKOUT_HIERARCHY_PASSWORD MUST be exported.");
                        if (!pOpts->shOverride)
                            LOG_ERROR("Environment variable MOCANA_TPM2_STORAGE_HIERARCHY_PASSWORD MUST be exported.");
                        if (!pOpts->lhOverride)
                            LOG_ERROR("Environment variable MOCANA_TPM2_ENDORSEMENT_HIERARCHY_PASSWORD MUST be exported.");
                    }
                    goto exit;
                }
            }
            else
            {
                LOG_ERROR("Following arguments MUST be specified --ehpwd, --shpwd, and --lhpwd.");
                goto exit;
            }
        }
    }

    if (FALSE == pOpts->ftpm)
    {
        /*
         * If clear is not requested, take ownership.
         */

        LOG_MESSAGE("Taking TPM ownership...");
        retval = takeOwnership(pOpts, pCtx);
        if (0 == retval)
            LOG_MESSAGE("TPM Ownership taken successfully.");
        else
            goto exit;
    }

    if (pOpts->credFileSupplied)
    {
        status = FMGMT_fopen (pOpts->credFile.buffer,"w", &pFile);
        if(OK != status)
        {
            LOG_ERROR("Failed to open credential file");
            goto exit;
        }
    }

    numCredentials = 3;

    if (0 < numCredentials)
    {
        status = DIGI_CALLOC((void **) &(entityCredentials.pEntityCredentials), numCredentials, sizeof(TAP_EntityCredential));

        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory; status %d", status);
            goto exit;
        }
        i = 0;
        {
            status = DIGI_CALLOC((void **) &(entityCredentials.pEntityCredentials[i].credentialList.pCredentialList), 1,
                    sizeof(TAP_Credential));
            if (OK != status)
            {
                LOG_ERROR("Failed to allocate memory; status %d", status);
                goto exit;
            }
            entityCredentials.pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_UNKNOWN;
            entityCredentials.pEntityCredentials[i].parentId = 0;
            entityCredentials.pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_TOKEN;
            entityCredentials.pEntityCredentials[i].entityId = TPM2_RH_ENDORSEMENT_ID;

            entityCredentials.pEntityCredentials[i].credentialList.numCredentials = 1;

            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[i].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[i].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[i].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[i].credentialData.bufferLen = pOpts->newEhAuthValue.size;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[i].credentialData.pBuffer = pOpts->newEhAuthValue.buffer;
            i++;
        }

        {
            status = DIGI_CALLOC((void **) &(entityCredentials.pEntityCredentials[i].credentialList.pCredentialList), 1,
                    sizeof(TAP_Credential));
            if (OK != status)
            {
                LOG_ERROR("Failed to allocate memory; status %d", status);
                goto exit;
            }
            entityCredentials.pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_UNKNOWN;
            entityCredentials.pEntityCredentials[i].parentId = 0;
            entityCredentials.pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_TOKEN;
            entityCredentials.pEntityCredentials[i].entityId = TPM2_RH_OWNER_ID;

            entityCredentials.pEntityCredentials[i].credentialList.numCredentials = 1;

            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = 1;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = 1;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = 3;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->newShAuthValue.size;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->newShAuthValue.buffer;
            i++;
        }

        {
            status = DIGI_CALLOC((void **) &(entityCredentials.pEntityCredentials[i].credentialList.pCredentialList), 1,
                    sizeof(TAP_Credential));
            if (OK != status)
            {
                LOG_ERROR("Failed to allocate memory; status %d", status);
                goto exit;
            }
            entityCredentials.pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_UNKNOWN;
            entityCredentials.pEntityCredentials[i].parentId = 0;
            entityCredentials.pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_MODULE;
            entityCredentials.pEntityCredentials[i].entityId = TPM2_RH_LOCKOUT_ID;

            entityCredentials.pEntityCredentials[i].credentialList.numCredentials = 1;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = 1;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = 1;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = 3;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->newLhAuthValue.size;
            entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->newLhAuthValue.buffer;
            i++;
        }
    }

    entityCredentials.numCredentials  = numCredentials;

    if (TRUE == pOpts->credFileSupplied)
    {
        status = MocSMP_PushCredentials(pFile, &entityCredentials,numCredentials,FALSE);
        if (OK != status)
        {
            LOG_ERROR("Failed to process configuration file; status %d", status);
            goto exit;
        }

        if (NULL != pFile)
        {
            FMGMT_fclose (&pFile);

            /* Base64 encode credentials file */
            status = DIGICERT_readFile((const char *)pOpts->credFile.buffer,
                    &pRawFileBuffer, &rawFileBufferLen);
            if (OK == status)
            {
                /* Convert to Base64 */
                status = BASE64_encodeMessage(pRawFileBuffer, rawFileBufferLen,
                        &pBase64Value, &base64ValueLen);
                if (OK == status)
                {
                    DIGICERT_writeFile((const char *)pOpts->credFile.buffer, pBase64Value, base64ValueLen);
                    LOG_MESSAGE("Credentials file encoded");
                }

                DIGICERT_freeReadFile(&pRawFileBuffer);

                /* For firmware TPM, a credentials file with well-known secrets is created */
                if (TRUE == pOpts->ftpm)
                    retval = 0;
            }
        }
    }

    /* Program DA lockout parameters, if atleast one DA parameter is specified */
    if (pOpts->daParameterSpecified && (FALSE == pOpts->ftpm))
    {
        hierarchyAuths.lockoutAuth = pOpts->newLhAuthValue;
        hierarchyAuths.forceUseLockoutAuth = TRUE;
        rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &hierarchyAuths);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to set hierarchy auths in FAPI2 context");
            goto exit;
        }

        rc = FAPI2_ADMIN_setDAParameters(pCtx, pOpts->maxAuthFailures,
                pOpts->recoveryTime, pOpts->lockoutRecoveryTime);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to set DA lockout parameters");
            goto exit;
        }
    }

exit:
    if (NULL != pFile)
    {
        FMGMT_fclose (&pFile);
    }

    if (NULL != pBase64Value)
        DIGI_FREE((void **)&pBase64Value);

    if (entityCredentials.pEntityCredentials)
    {   
        for (i = 0; i < numCredentials; i++)
        {
            if (entityCredentials.pEntityCredentials[i].credentialList.pCredentialList)
                DIGI_FREE((void **)&entityCredentials.pEntityCredentials[i].credentialList.pCredentialList);
        }

        DIGI_FREE((void **)&entityCredentials.pEntityCredentials);
    }     
    if (pCtx)
    {
        rc = FAPI2_CONTEXT_uninit(&pCtx);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to free FAPI2 context");
            retval = -1;
        }
    }

    return retval;
}

int main(int argc, char *argv[])
{
    int retval = -1;
    cmdLineOpts *pOpts = NULL;
    platformParseCmdLineOpts platCmdLineParser = NULL;

#if defined (__RTOS_LINUX__) || defined (__RTOS_OSX__) || defined (__RTOS_WIN32__)
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

    if (0 != (retval = executeOptions(pOpts)))
    {
        if ((ERR_TAKEOWNERSHIP_ALREADY_DONE == retval) || 
                (ERR_PROVISIONING_ALREADY_DONE == retval))
            TPM2_DEBUG_PRINT_NO_ARGS("Unable to retake TPM ownership.");
        else
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to take TPM ownership.");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
    {
        if (ERR_TAKEOWNERSHIP_ALREADY_DONE == retval)
            LOG_MESSAGE("INFO: *****TPM ownership already taken successfully*****");
        else
            LOG_ERROR("*****digicert_tpm2_takeownership failed to complete successfully.*****");
    }

    DIGICERT_freeDigicert();
    return retval;
}
