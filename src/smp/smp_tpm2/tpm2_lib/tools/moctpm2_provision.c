/*
 * moctpm2_provision.c
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
#include "../../smp_tap_tpm2.h"
#include "../../smp_tpm2.h"
#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../../common/mcmdline.h"
#endif

extern MSTATUS MocTap_FreeUsageCredentials(TAP_EntityCredentialList **pUsageCred);

extern MSTATUS
MocTap_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen,
      TAP_EntityCredentialList **pUsageCredentials) ;

extern MSTATUS MocSMP_PushCredentials(FileDescriptor pFile, TAP_EntityCredentialList* pEntityCredentials,
                        int numCredentials,byteBoolean provision);
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

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean endorsementAuthSpecified;
    TPM2B_AUTH endorsementAuthValue;

    byteBoolean storageAuthSpecified;
    TPM2B_AUTH storageAuthValue;

    byteBoolean lockoutAuthSpecified;
    TPM2B_AUTH lockoutAuthValue;

    byteBoolean useEkAuthValue;
    TPM2B_AUTH ekAuthValue;

    byteBoolean useSrkAuthValue;
    TPM2B_AUTH srkAuthValue;

    byteBoolean ekAlgSpecified;
    TPMI_ALG_PUBLIC ekKeyAlg;

    byteBoolean srkAlgSpecified;
    TPMI_ALG_PUBLIC srkKeyAlg;

    byteBoolean serverNameSpecified;
    byteBoolean credFileSupplied;
    byteBoolean credFileDisabled;

    TPM2B_AUTH credFile;
    char serverName[SERVER_NAME_LEN];
    ubyte4 serverNameLen;
    ubyte4 serverPort;
} cmdLineOpts;

TAP_Buffer userCredBuf = {0} ;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_provision: Help Menu\n");
    LOG_MESSAGE("This tool creates the Endorsement Key (EK) and Storage Root Key (SRK). The\n"
                "EK is created with either the endorsement hierarchy password provided with\n"
                "the --ekpwd option or with the password provided with the --ehpwd option \n"
                "(if --ekpwd option is not specified). The SRK is created with the password \n"
                "provided with --srkpwd or the password provided with --shpwd option \n"
                "(if --srkpwd option is not specified).\n");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h");
    LOG_MESSAGE("                   Help menu");
    LOG_MESSAGE("           --sm=[server name or module path]");
    LOG_MESSAGE("                   (Mandatory) Specify the Security Module; use localhost for the TPM\n"
            "                       emulator or module path for the hardware TPM (e.g. /dev/tpm0).");
    LOG_MESSAGE("           --ep=[server port]");
    LOG_MESSAGE("                   Specify the port number for the TPM emulator (applicable only for --sm=localhost).");
    LOG_MESSAGE("           --ehpwd=[password]");
    LOG_MESSAGE("                   (Mandatory) Specify password for the endorsement hierarchy. If --ekpwd is not specified, this\n"
                "                   password will be used for the Endorsement key. If no password is specified, the well known\n"
                "                   password is used. Password must be provided with quotes.");
    LOG_MESSAGE("           --shpwd=[password]");
    LOG_MESSAGE("                   (Mandatory) Specify password for the storage hierarchy. If no password is specified the well-\n"
                "                   known password is used. Password must be provided with quotes.");
    LOG_MESSAGE("           --ekpwd=[password]");
    LOG_MESSAGE("                   Specify the Endorsement Key (EK) password. If this option is used, the provided password is\n"
                "                   used for the EK. If no password is specified, the endorsement hierarchy password is used.\n"
                "                   Password must be provided with quotes.");
    LOG_MESSAGE("           --srkpwd=[password]");
    LOG_MESSAGE("                   Storage Root Key password. If this option is used, the password provided\n"
                "                   here will be used for the SRK. Password must be provided with quotes.\n"
                "                   If no [password] is specified with this option, the storage hierarchy password will be used.");
    LOG_MESSAGE("           --ekalg=[ecc or rsa]");
    LOG_MESSAGE("                   (Mandatory) Specify the algorithm (ecc or rsa) to create the EK.");
    LOG_MESSAGE("           --srkalg=[ecc or rsa]");
    LOG_MESSAGE("                   (Mandatory) Specify the algorithm (ecc or rsa) to create the SRK.");
    LOG_MESSAGE("           --nocredfile");
    LOG_MESSAGE("                   Disables generation and use of the credentials file. The required credentials must be\n"
                "                   specified as command line arguments or environment variables");
    LOG_MESSAGE("           --credfile=[Credentials file name]");
    LOG_MESSAGE("                   Credentials file that comprises of encoded passwords required to use the TPM\n");
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
            {"sm", required_argument, NULL, 2},
            {"ep", required_argument, NULL, 3},
            {"ehpwd", required_argument, NULL, 4},
            {"shpwd", required_argument, NULL, 5},
            {"ekpwd", required_argument, NULL, 6},
            {"ekalg", required_argument, NULL, 7},
            {"srkalg", required_argument, NULL, 8},
            {"credfile", required_argument, NULL, 9},
            {"srkpwd",required_argument, NULL, 10},
            {"nocredfile", no_argument, NULL, 11},
            {NULL, 0, NULL, 0},
    };
    sbyte4 cmpResult = 0;

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
                LOG_ERROR("--sm Server name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                    pOpts->serverNameLen))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->serverName[pOpts->serverNameLen] = '\0';
            TPM2_DEBUG_PRINT("TPM2 Security Module name: %s", pOpts->serverName);
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

        case 4:
            pOpts->endorsementAuthSpecified = TRUE;

            pOpts->endorsementAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->endorsementAuthValue.size > sizeof(pOpts->endorsementAuthValue.buffer))
            {
                LOG_ERROR("--ehpwd Password Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->endorsementAuthValue.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->endorsementAuthValue.buffer, optarg, pOpts->endorsementAuthValue.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->endorsementAuthValue.buffer[pOpts->endorsementAuthValue.size] = '\0';
            TPM2_DEBUG_PRINT("Endorsement password: %s", pOpts->endorsementAuthValue.buffer);

            break;

        case 5:
            pOpts->storageAuthSpecified = TRUE;

            pOpts->storageAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->storageAuthValue.size > sizeof(pOpts->storageAuthValue.buffer))
            {
                LOG_ERROR("--shpwd Password Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->storageAuthValue.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->storageAuthValue.buffer, optarg, pOpts->storageAuthValue.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->storageAuthValue.buffer[pOpts->storageAuthValue.size] = '\0';
            TPM2_DEBUG_PRINT("Storage password: %s", pOpts->storageAuthValue.buffer);
            break;

        case 6:
            pOpts->useEkAuthValue = TRUE;

            pOpts->ekAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->ekAuthValue.size > sizeof(pOpts->ekAuthValue.buffer))
            {
                LOG_ERROR("--ekpwd Password Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->ekAuthValue.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->ekAuthValue.buffer, optarg, pOpts->ekAuthValue.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->ekAuthValue.buffer[pOpts->ekAuthValue.size] = '\0';
            TPM2_DEBUG_PRINT("New EK password: %s", pOpts->ekAuthValue.buffer);
            break;

        case 7:
            pOpts->ekAlgSpecified = TRUE;

            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--ekalg EK algorithm not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"rsa",
                    DIGI_STRLEN((const sbyte *)"rsa"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->ekKeyAlg = TPM2_ALG_RSA;
                TPM2_DEBUG_PRINT_NO_ARGS("Creating RSA EK");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"ecc",
                    DIGI_STRLEN((const sbyte *)"ecc"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->ekKeyAlg = TPM2_ALG_ECC;
                TPM2_DEBUG_PRINT_NO_ARGS("Creating ECC EK");
                break;
            }

            LOG_ERROR("--ekalg not ecc or rsa");
            goto exit;
            break;

        case 8:
            pOpts->srkAlgSpecified = TRUE;

            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--srkalg SRK algorithm not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"rsa",
                    DIGI_STRLEN((const sbyte *)"rsa"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->srkKeyAlg = TPM2_ALG_RSA;
                TPM2_DEBUG_PRINT_NO_ARGS("Creating RSA SRK");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"ecc",
                    DIGI_STRLEN((const sbyte *)"ecc"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->srkKeyAlg = TPM2_ALG_ECC;
                TPM2_DEBUG_PRINT_NO_ARGS("Creating ECC SRK");
                break;
            }
            LOG_ERROR("--srkalg not ecc or rsa.");
            goto exit;
            break;

        case 9: 
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
                LOG_ERROR("--credfile value invalid or starts with dash.");
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

        case 10:
            pOpts->useSrkAuthValue = TRUE;

            pOpts->srkAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->srkAuthValue.size > sizeof(pOpts->srkAuthValue.buffer))
            {
                LOG_ERROR("--srkpwd Password Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->srkAuthValue.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->srkAuthValue.buffer, optarg, pOpts->srkAuthValue.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->srkAuthValue.buffer[pOpts->srkAuthValue.size] = '\0';
            TPM2_DEBUG_PRINT("New SRK password: %s", pOpts->srkAuthValue.buffer);
            break;

        case 11:
            pOpts->credFileDisabled = TRUE;
            TPM2_DEBUG_PRINT_1("Credentials file disabled");
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

int createPrimaryKeys(cmdLineOpts *pOpts, FAPI2_CONTEXT *pCtx)
{
    int retval = -1;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    AdminCreateSRKIn srkIn = { 0 };
    AdminCreateEKIn ekIn = { 0 };
    ContextSetHierarchyAuthIn hierarchyAuths = { 0 };
    ContextGetPrimaryObjectNameIn objectNameIn = { 0 };
    ContextGetPrimaryObjectNameOut objectName = { 0 };
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    /*TAP_Buffer userCredBuf = {0} ;*/
    MSTATUS status= OK;
    int numCredentials = 0;
    ubyte *pRawBuffer = NULL;
    ubyte4 rawBufferLen = 0;

    if (!pOpts || !pCtx)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid parameter.");
        goto exit;
    }

    if(pOpts->credFileSupplied)
    {
        status = DIGICERT_readFile((const char*)pOpts->credFile.buffer, &pRawBuffer,
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
            switch(pEntityCredentials->pEntityCredentials[numCredentials -1].entityId)
            {
                case TPM2_RH_OWNER_ID:
                    pOpts->storageAuthValue.size = pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.bufferLen;
                    DIGI_MEMCPY(pOpts->storageAuthValue.buffer,pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.pBuffer,pOpts->storageAuthValue.size);
                    hierarchyAuths.ownerAuth = pOpts->storageAuthValue;
                    break;

                case TPM2_RH_ENDORSEMENT_ID:
                    pOpts->endorsementAuthValue.size = pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.bufferLen;
                    DIGI_MEMCPY(pOpts->endorsementAuthValue.buffer, pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.pBuffer, pOpts->endorsementAuthValue.size);
                    hierarchyAuths.endorsementAuth =  pOpts->endorsementAuthValue;
                    break;
                case TPM2_RH_LOCKOUT_ID:
                    hierarchyAuths.lockoutAuth.size =  pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.bufferLen;
                    DIGI_MEMCPY(hierarchyAuths.lockoutAuth.buffer, pEntityCredentials->pEntityCredentials[numCredentials -1].credentialList.pCredentialList[0].credentialData.pBuffer, hierarchyAuths.lockoutAuth.size);
                    break;

            }
            numCredentials = numCredentials -1;
        }
    }
    else
    {
        hierarchyAuths.lockoutAuth = pOpts->lockoutAuthValue;
        hierarchyAuths.ownerAuth = pOpts->storageAuthValue;
        hierarchyAuths.endorsementAuth = pOpts->endorsementAuthValue;
    }
    hierarchyAuths.forceUseEndorsementAuth = TRUE;
    hierarchyAuths.forceUseOwnerAuth = TRUE;
    hierarchyAuths.forceUseLockoutAuth = TRUE;
    rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &hierarchyAuths);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to set hierarchy auths in FAPI2 context");
        goto exit;
    }

    ekIn.isPrivacySensitive = TRUE;
    ekIn.keyAlg = pOpts->ekKeyAlg;
    if (pOpts->useEkAuthValue)
        ekIn.EKAuth = pOpts->ekAuthValue;
    else
    {
        pOpts->ekAuthValue = pOpts->endorsementAuthValue;
        ekIn.EKAuth = pOpts->endorsementAuthValue;
    }

     if (pOpts->useSrkAuthValue)
        srkIn.SRKAuth = pOpts->srkAuthValue;
    else
    {
        pOpts->srkAuthValue = pOpts->storageAuthValue;
        srkIn.SRKAuth = pOpts->storageAuthValue;
    }

    /*
     * Create EK only if it does not already exist.
     */
    objectNameIn.persistentHandle = FAPI2_RH_EK;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pCtx, &objectNameIn, &objectName);
    if (TSS2_RC_SUCCESS != rc)
    {
        rc = FAPI2_ADMIN_createEK(pCtx, &ekIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            LOG_ERROR("Failed to create EK. rc = 0x%02x", (unsigned int)rc);
            goto exit;
        }
    }
    else
    {
        TPM2_DEBUG_PRINT_NO_ARGS("EK already created. Skipping EK Creation.");
    }

    /*
     * Create EK only if it does not already exist.
     */
    objectNameIn.persistentHandle = FAPI2_RH_SRK;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pCtx, &objectNameIn, &objectName);
    if (TSS2_RC_SUCCESS != rc)
    {
        srkIn.keyAlg = pOpts->srkKeyAlg;
        rc = FAPI2_ADMIN_createSRK(pCtx, &srkIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            LOG_ERROR("Failed to create SRK. rc = 0x%02x", (unsigned int)rc);
            goto exit;
        }
    }
    else
    {
        TPM2_DEBUG_PRINT_NO_ARGS("SRK already created. Skipping SRK Creation.");
    }

    retval = 0;
exit:
    if(NULL != pRawBuffer)
        DIGI_FREE((void**)&pRawBuffer);

    if(NULL != pEntityCredentials)
        MocTap_FreeUsageCredentials(&pEntityCredentials);

    return retval;
}

MSTATUS getCredentialsFromEnvironment(cmdLineOpts *pOpts)
{
    MSTATUS status = ERR_INVALID_ARG;
    char *pEnv = NULL;
    int envLen = 0;

    if (NULL == pOpts)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    {
#ifdef MOCANA_ALLOW_SAME_PWD
        pEnv = getenv("DIGICERT_TPM2_ALL_HIERARCHIES_PASSWORD");
        if (pEnv)
        {
            envLen = DIGI_STRLEN((const sbyte *)pEnv);
            if ((envLen >= sizeof(pOpts->lockoutAuthValue.buffer)) ||
                (envLen >= sizeof(pOpts->storageAuthValue.buffer)) ||
                (envLen >= sizeof(pOpts->endorsementAuthValue.buffer)))
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            DIGI_MEMCPY(pOpts->lockoutAuthValue.buffer, pEnv, envLen);
            pOpts->lockoutAuthValue.size = envLen;
            pOpts->lockoutAuthValue.buffer[envLen] = '\0';
            pOpts->lockoutAuthSpecified = TRUE;

            DIGI_MEMCPY(pOpts->storageAuthValue.buffer, pEnv, envLen);
            pOpts->storageAuthValue.size = envLen;
            pOpts->storageAuthValue.buffer[envLen] = '\0';
            pOpts->storageAuthSpecified = TRUE;

            DIGI_MEMCPY(pOpts->endorsementAuthValue.buffer, pEnv, envLen);
            pOpts->endorsementAuthValue.size = envLen;
            pOpts->endorsementAuthValue.buffer[envLen] = '\0';
            pOpts->endorsementAuthSpecified = TRUE;

            status = OK;
        }
        else
#endif
        {
            pEnv = getenv("DIGICERT_TPM2_LOCKOUT_HIERARCHY_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->lockoutAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->lockoutAuthValue.buffer, pEnv, envLen);
                pOpts->lockoutAuthValue.size = envLen;
                pOpts->lockoutAuthValue.buffer[envLen] = '\0';
                pOpts->lockoutAuthSpecified = TRUE;
            }

            pEnv = getenv("DIGICERT_TPM2_STORAGE_HIERARCHY_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->storageAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->storageAuthValue.buffer, pEnv, envLen);
                pOpts->storageAuthValue.size = envLen;
                pOpts->storageAuthValue.buffer[envLen] = '\0';
                pOpts->storageAuthSpecified = TRUE;
            }

            pEnv = getenv("DIGICERT_TPM2_ENDORSEMENT_HIERARCHY_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->endorsementAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->endorsementAuthValue.buffer, pEnv, envLen);
                pOpts->endorsementAuthValue.size = envLen;
                pOpts->endorsementAuthValue.buffer[envLen] = '\0';
                pOpts->endorsementAuthSpecified = TRUE;
            }

            pEnv = getenv("DIGICERT_TPM2_EK_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->ekAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->ekAuthValue.buffer, pEnv, envLen);
                pOpts->ekAuthValue.size = envLen;
                pOpts->ekAuthValue.buffer[envLen] = '\0';
                pOpts->useEkAuthValue = TRUE;
            }

            pEnv = getenv("DIGICERT_TPM2_SRK_PASSWORD");
            if (pEnv)
            {
                envLen = DIGI_STRLEN((const sbyte *)pEnv);
                if (envLen >= sizeof(pOpts->srkAuthValue.buffer))
                {
                    status = ERR_BUFFER_OVERFLOW;
                    goto exit;
                }

                DIGI_MEMCPY(pOpts->srkAuthValue.buffer, pEnv, envLen);
                pOpts->srkAuthValue.size = envLen;
                pOpts->srkAuthValue.buffer[envLen] = '\0';
                pOpts->useSrkAuthValue = TRUE;
            }

            if (pOpts->useSrkAuthValue && pOpts->useEkAuthValue &&
                    pOpts->endorsementAuthSpecified && pOpts->storageAuthSpecified)
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
    ContextIsTpmProvisionedOut isTpmProvisioned = { 0 };
    MSTATUS status = OK;
    ubyte *pBase64Value = NULL;
    ubyte4 base64ValueLen = 0;
    ubyte *pRawFileBuffer = NULL;
    ubyte4 rawFileBufferLen = 0;
    TAP_EntityCredentialList entityCredentials = { 0 } ;
    int i = 0, numCredentials = 0;
    FileDescriptor pFile = NULL;
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

    if (!pOpts->serverNameSpecified || !pOpts->ekAlgSpecified || !pOpts->srkAlgSpecified)
    {
        if (pOpts->credFileDisabled)
            LOG_ERROR("One of mandatory option --sm, --ekalg or --srkalg not specified");
        else
            LOG_ERROR("One of mandatory option --sm, --ekalg, --srkalg, --ehpwd or --shpwd not specified");

        goto exit;
    }

    if (!pOpts->credFileSupplied && !pOpts->credFileDisabled)
    {
        LOG_ERROR("One of mandatory option --nocredfile or --credfile not specified.");
        goto exit;
    }

    initFlag = 1;
    rc = FAPI2_CONTEXT_init(&pCtx,  pOpts->serverNameLen,
            (ubyte *)pOpts->serverName, pOpts->serverPort, 3, &initFlag);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to create FAPI2 context.");
        goto exit;
    }

    rc = FAPI2_CONTEXT_isTpmProvisioned(pCtx, &isTpmProvisioned);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed isTpmProvisioned.");
        goto exit;
    }

    if (isTpmProvisioned.provisioned)
    {
        LOG_MESSAGE("TPM already provisioned");
        retval = 0;
        goto exit;
    }

    rc = FAPI2_CONTEXT_getMaxAuthValueLength(pCtx, &maxAuthValueLen);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Could not get maximum authValue lengths");
        goto exit;
    }

    if (pOpts->credFileDisabled)
    {
        /* If we don't have command line arguments get credentials from environment variables */
        if (!(pOpts->endorsementAuthSpecified &&
                pOpts->storageAuthSpecified &&
                pOpts->useEkAuthValue && pOpts->useSrkAuthValue))
        {
            if (OK != getCredentialsFromEnvironment(pOpts))
            {
                if (!pOpts->endorsementAuthSpecified)
                    LOG_ERROR("Environment option MOCANA_TPM2_ENDORSEMENT_PASSWORD must be used to specify the Endorsement hierarchy password");
                if (!pOpts->storageAuthSpecified)
                    LOG_ERROR("Environment option MOCANA_TPM2_STORAGE_PASSWORD must be used to specify the Storage hierarchy password");
                if (!pOpts->useEkAuthValue)
                    LOG_ERROR("Environment option MOCANA_TPM2_EK_PASSWORD must be used to specify the Endorsement Key password");
                if (!pOpts->useSrkAuthValue)
                    LOG_ERROR("Environment option MOCANA_TPM2_SRK_PASSWORD must be used to specify the Storage Root Key password");
                goto exit;
            }
        }
    }

    if (pOpts->endorsementAuthValue.size > maxAuthValueLen.hierarchyAuthValueLen)
    {
        LOG_ERROR("Endorsement hierarchy password length greater than supported size. "
                "Password length: %d, max: %d", pOpts->endorsementAuthValue.size,
                maxAuthValueLen.hierarchyAuthValueLen);
        goto exit;
    }

    if (pOpts->storageAuthValue.size > maxAuthValueLen.hierarchyAuthValueLen)
    {
        LOG_ERROR("Storage hierarchy password length greater than supported size. "
                "Password length: %d, max: %d", pOpts->storageAuthValue.size,
                maxAuthValueLen.hierarchyAuthValueLen);
        goto exit;
    }

    if (pOpts->ekAuthValue.size > maxAuthValueLen.objectAuthValueLen)
    {
        LOG_ERROR("EK password length greater than supported size. "
                "Password length: %d, max: %d", pOpts->ekAuthValue.size,
                maxAuthValueLen.objectAuthValueLen);
        goto exit;
    }

    if (pOpts->srkAuthValue.size > maxAuthValueLen.objectAuthValueLen)
    {
        LOG_ERROR("EK password length greater than supported size. "
                "Password length: %d, max: %d", pOpts->srkAuthValue.size,
                maxAuthValueLen.objectAuthValueLen);
        goto exit;
    }

    retval = createPrimaryKeys(pOpts, pCtx);
    if (0 == retval)
    {
        LOG_MESSAGE("Successfully created EK and SRK.");
    }

    if (pOpts->credFileSupplied)
    {
        numCredentials = 2;

        if (0 < numCredentials)
        {
            status = DIGI_CALLOC((void **) &(entityCredentials.pEntityCredentials), numCredentials, sizeof(TAP_EntityCredential));
            if (OK != status)
            {
                LOG_ERROR("Failed to allocate memory for credentials structure status %d", status);
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
                entityCredentials.pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_TOKEN;
                entityCredentials.pEntityCredentials[i].parentId = TPM2_RH_ENDORSEMENT;
                entityCredentials.pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_OBJECT;
                entityCredentials.pEntityCredentials[i].entityId = TPM2_RH_EK;

                entityCredentials.pEntityCredentials[i].credentialList.numCredentials = 1;

                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->ekAuthValue.size;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->ekAuthValue.buffer;
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

                entityCredentials.pEntityCredentials[i].parentType = TAP_ENTITY_TYPE_TOKEN;
                entityCredentials.pEntityCredentials[i].parentId = TPM2_RH_OWNER;
                entityCredentials.pEntityCredentials[i].entityType = TAP_ENTITY_TYPE_OBJECT;
                entityCredentials.pEntityCredentials[i].entityId = TPM2_RH_SRK;

                entityCredentials.pEntityCredentials[i].credentialList.numCredentials = 1;

                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.bufferLen = pOpts->srkAuthValue.size;
                entityCredentials.pEntityCredentials[i].credentialList.pCredentialList[0].credentialData.pBuffer = pOpts->srkAuthValue.buffer;
                i++;
            }
        }

        status = DIGICERT_writeFile((const char*)pOpts->credFile.buffer, userCredBuf.pBuffer, userCredBuf.bufferLen);
        if(OK != status)
        {
            LOG_ERROR("Failed to update credential file; status %d", status);
            goto exit;
        }

        status = FMGMT_fopen (pOpts->credFile.buffer,"a+", &pFile);
        if(OK != status)
        {
            LOG_ERROR("Failed to open credential file");
            goto exit;
        }

        status = MocSMP_PushCredentials(pFile, &entityCredentials,numCredentials,TRUE);
        if(OK != status)
        {
            LOG_ERROR("Failed to write credential file; status %d", status);
            goto exit;
        }
    }
exit:
    if(NULL != pFile)
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

    if (entityCredentials.pEntityCredentials)
    {
        for (i = 0; i < numCredentials; i++)
        {
            if (entityCredentials.pEntityCredentials[i].credentialList.pCredentialList)
                DIGI_FREE((void **)&entityCredentials.pEntityCredentials[i].credentialList.pCredentialList);
        }

        DIGI_FREE((void **)&entityCredentials.pEntityCredentials);
    }

    if (NULL != pBase64Value)
        DIGI_FREE((void **)&pBase64Value);

    if (pCtx)
    {
        rc = FAPI2_CONTEXT_uninit(&pCtx);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to free FAPI2 context");
            retval = -1;
        }
    }
    
    if(NULL != userCredBuf.pBuffer)
        DIGI_FREE((void**)&(userCredBuf.pBuffer));
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
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to provision TPM.");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("*****digicert_tpm2_provision failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}
