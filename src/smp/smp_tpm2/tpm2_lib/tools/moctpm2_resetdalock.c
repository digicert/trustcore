/*
 * moctpm2_resetdalock.c
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

#define SERVER_NAME_LEN 256

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

extern  MSTATUS MocTap_FreeUsageCredentials(TAP_EntityCredentialList **pUsageCred);

typedef struct {
    byteBoolean exitAfterParse;
    byteBoolean serverNameSpecified;
    byteBoolean credFileSupplied;
    byteBoolean wellKnownAuthSupplied;
    byteBoolean credFileDisabled;
    byteBoolean oldLockoutAuthSupplied;

    /*
     * Current/old lockout auth required to clear the TPM lockout
     */
    TPM2B_AUTH oldLockoutAuth;

    TPM2B_AUTH credFile;

    char serverName[SERVER_NAME_LEN];
    ubyte4 serverNameLen;
    ubyte4 serverPort;
    ubyte4 wellKnownAuthLen;
} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("This tool clears TPM 2.0 Dictionary Attack lockout.\n"); 

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h");
    LOG_MESSAGE("                   Help menu");
    LOG_MESSAGE("           --sm=[server name or module path]");
    LOG_MESSAGE("                   (Mandatory) Specify the Security Module; use localhost for the TPM\n"
            "                       emulator or module path for the hardware TPM (e.g. /dev/tpm0).");
    LOG_MESSAGE("           --ep=[server port]");
    LOG_MESSAGE("                   Specify the port number for the TPM emulator (applicable only for --sm=localhost).");
    LOG_MESSAGE("           --credfile=[credentials file]");
    LOG_MESSAGE("                   (Mandatory) Credentials file that comprises of encoded passwords required to use the TPM.");
    LOG_MESSAGE("           --z");
    LOG_MESSAGE("                   Authenticate using Well Known password.");
    LOG_MESSAGE("           --lhpwd=[password]");
    LOG_MESSAGE("                   Specify the Lockout Hierarchy password. This is needed for clearing the DA lockout condition.\n"
                "                   Password must be provided with quotes.");
    LOG_MESSAGE("           --nocredfile");
    LOG_MESSAGE("                   Disables use of the credentials file. The lockout credential must be\n"
                "                   specified as command line argument (--lhpwd) or environment variable\n"
                "                   (MOCANA_TPM2_OLD_LOCKOUT_PASSWORD)\n");
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
            {"ep", required_argument, NULL, 2},
            {"sm", required_argument, NULL, 3},
            {"credfile", required_argument, NULL, 4},
            {"z", no_argument, NULL, 5},
            {"lhpwd", required_argument, NULL, 6},
            {"nocredfile", no_argument, NULL, 7},
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
            case 3:
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
                    LOG_ERROR("-sm security module name not specified");
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

            case 4:
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

            case 5:
 
                pOpts->wellKnownAuthSupplied = TRUE;
                pOpts->oldLockoutAuth.size = 0;
                DIGI_MEMSET(pOpts->oldLockoutAuth.buffer, 0, sizeof( pOpts->oldLockoutAuth.buffer));

                TPM2_DEBUG_PRINT_1("Well Known Auth Option Specified: " );
                break;  

            case 6:
                pOpts->oldLockoutAuthSupplied = TRUE;
                /*
                 * lockout auth can be the EmptyBuffer. so --lhpwd with nothing following
                 * it implies EmptyBuffer.
                 */

                pOpts->oldLockoutAuth.size = DIGI_STRLEN((const sbyte *)optarg);
                if (pOpts->oldLockoutAuth.size > sizeof(pOpts->oldLockoutAuth.buffer))
                {
                    LOG_ERROR("-lhpwd Password Length too long. Max size: %u bytes",
                            (unsigned int)sizeof(pOpts->oldLockoutAuth.buffer));
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->oldLockoutAuth.buffer, optarg, pOpts->oldLockoutAuth.size))
                {
                    TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                    goto exit;
                }
                pOpts->oldLockoutAuth.buffer[pOpts->oldLockoutAuth.size] = '\0';
                TPM2_DEBUG_PRINT("Lockout password: %s", pOpts->oldLockoutAuth.buffer);

                break;

            case 7:
                if (TRUE == pOpts->credFileSupplied)
                {
                    LOG_ERROR("--credfile cannot be specified with --nocredfile option");
                    pOpts->exitAfterParse = TRUE;
                    goto exit;
                }
                pOpts->credFileDisabled = TRUE;

                TPM2_DEBUG_PRINT_1("Credentials file option disabled\n");
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

int clearLockedOutTpm(cmdLineOpts *pOpts, FAPI2_CONTEXT *pCtx)
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
    FileDescriptor pFile = NULL;

    if (!pOpts || !pCtx)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameter.");
        goto exit;
    }

    if((!pOpts->credFileDisabled) && (!pOpts->credFileSupplied))
    {
        LOG_ERROR(" One of --credfile or --nocredfile options must be provided");
        goto exit;
    } 

    if (pOpts->credFileSupplied && pOpts->wellKnownAuthSupplied)
    {
        LOG_ERROR(" --z cannot be specified with --credfile option");
        goto exit;
    }

    if (pOpts->oldLockoutAuthSupplied && pOpts->wellKnownAuthSupplied)
    {
        LOG_ERROR(" --z cannot be specified with --lhpwd option");
        goto exit;
    }

    if(pOpts->wellKnownAuthSupplied)
    {
        LOG_MESSAGE(" Using Default Password");
    }
    else
    {
        if(pOpts->credFileSupplied)
        {
            status = FMGMT_fopen (pOpts->credFile.buffer,"r", &pFile);
            if (OK == status)
            {
                ch = FMGMT_fgetc (pFile);
                if (ch == MOC_EOF)
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
            else
            {
                LOG_ERROR("Failed to open file %s", (const char *)pOpts->credFile.buffer);
                goto exit;
            }
        }
        else
        {
            if (!pOpts->oldLockoutAuthSupplied)
            {
                sbyte *pEnv = NULL;
                int envLen = 0;

                /* Attempt to get it from environment variable */
                status = FMGMT_getEnvironmentVariableValueAlloc ("MOCANA_TPM2_LOCKOUT_HIERARCHY_PASSWORD", &pEnv);
                if (OK == status)
                {
                    envLen = DIGI_STRLEN((const sbyte *)pEnv);
                    if (envLen > sizeof(pOpts->oldLockoutAuth.buffer))
                    {
                        LOG_ERROR("Lockout auth value length should be less than %d bytes",
                                (int)sizeof(pOpts->oldLockoutAuth.buffer));
                        status = ERR_BUFFER_OVERFLOW;
                        DIGI_FREE ((void **) &pEnv);
                        goto exit;
                    }

                    DIGI_MEMCPY(pOpts->oldLockoutAuth.buffer, pEnv, envLen);
                    pOpts->oldLockoutAuth.size = envLen;
                }

                DIGI_FREE ((void **) &pEnv);
            }
        }
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
    rc = FAPI2_ADMIN_clearDALockout(pCtx);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to reset locked out TPM. rc = 0x%02x",  (unsigned int)rc);
        goto exit;
    }
    
    retval = 0;
exit:
    if (NULL != userCredBuf.pBuffer)
        DIGI_FREE((void **)&userCredBuf.pBuffer);

    if(NULL != pRawBuffer)
        DIGICERT_freeReadFile(&pRawBuffer);
    if(NULL != pEntityCredentials)
        MocTap_FreeUsageCredentials(&pEntityCredentials) ;
    if (TSS2_RC_SUCCESS != rc)
        retval = -1;
    return retval;
}

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pCtx = NULL;
    ContextGetAuthValueLengthOut maxAuthValueLen = { 0 };
    int initFlag = 0;

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
        LOG_ERROR("--s must be specified. Server/Module name is required.");
        goto exit;
    }

    initFlag = 1;
    rc = FAPI2_CONTEXT_init(&pCtx, pOpts->serverNameLen,
            (ubyte *)pOpts->serverName, pOpts->serverPort, 3, &initFlag);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to create FAPI2 context.");
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

    LOG_MESSAGE("Clearing TPM lockout reset...");
    retval = clearLockedOutTpm(pOpts, pCtx);
    if (0 == retval)
        LOG_MESSAGE("Cleared TPM lockout successfully.");
    else
        LOG_MESSAGE("Failed to clear TPM lockout.");

exit:

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

    if (0 != executeOptions(pOpts))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to clear Dictionary lockout condition on TPM.");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("*****digicert_tpm2_resetdalock failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}
