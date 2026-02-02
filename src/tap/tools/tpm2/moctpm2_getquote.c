/**
 @file moctpm2_getquote.c

 @page digicert_tpm2_getquote

 @ingroup tap_tools_tpm2_commands

 @htmlonly
 <h1>NAME</h1>
 digicert_tpm2_getquote -
 @endhtmlonly
 Generates a quote from an input file using TPM 2.0 secure element.

 # SYNOPSIS
 `digicert_tpm2_getquote [options]`

 # DESCRIPTION
 <B>digicert_tpm2_getquote</B> This tool generates a TPM quote (a hash of specified PCRs, and a signature of the hash) using a nonce provided in an input file.

@verbatim
    --h [display command line options]
        Help menu
    --conf=[TPM 2.0 configuration file]
        Path to TPM 2.0 module configuration file.
    --s=[server name]
        Host on which TPM chip is located. This can be 'localhost' or a         
        remote host running a TAP server.
    --p=[server port]
        Port on which the TPM server is listening.
    --modulenum=[module num]
        Specify the module num to use. If not provided, the first module found is used
    --kpwd=[key password]
        Password of the key to be loaded.
    --halg=[hash algorithm]
        (Mandatory) Hash algorithm (sha1, sha256, sha384 or sha512) for the hash of the TPM quote.
    --tdidx=[PCR index]
        (Optional) The PCR index to use. Multiple PCR indexes may be specified by repeating this option.
    --pri=[input private key file]
        (Mandatory) Input file name that contains the Private key
    --idf=[input data file]
        (Mandatory) Input file that contains the nonce (maximum of 32 bytes).
    --odf=[output data file]
        (Mandatory) Output file to write the TPM quote to.
    --osf=[output Signature file]
        Output file that contain a signature of the TPM quote.
@endverbatim

  <p> If Unicode is enabled at compile time, you will also see the following options:

@verbatim
    -u [unicode]
        Use UNICODE encoding for passwords.
@endverbatim

 # Reporting Bugs
  Report bugs to <Support@digicert.com>

 * Trust Anchor Platform TPM 2.0 utility function APIs
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
#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mocana.h"
#include "../../../common/mdefs.h"
#include "../../../common/mstdlib.h"
#include "../../../common/mprintf.h"
#include "../../../common/debug_console.h"
#include "../../../common/vlong.h"
#include "../../../crypto/sha1.h"
#include "../../../crypto/sha256.h"
#include "../../../crypto/sha512.h"
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../../../data_protection/file_protect.h"
#endif
#include "../../tap_api.h"
#include "../../tap_smp.h"
#include "../../tap_utils.h"
#include "../../tap_serialize.h"
#include "../../tap_serialize_smp.h"
#include "../moctap_tools_utils.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../common/mcmdline.h"
#endif

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#else
#include "../../../common/tpm2_path.h"
#endif

typedef struct 
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define MAX_CMD_BUFFER 4096
#define MAX_PCR_REGISTERS 64

#define TPM2_DEBUG_PRINT_1(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define TPM2_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#define PRINT_STATUS(x,y)   \
    DB_PRINT("%s %s status %d = %s\n", x, (y==OK ? "SUCCESS":"FAILED"),\
                y, MERROR_lookUpErrorCode(y))

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean keyAuthSpecified;
    TAP_Buffer keyAuthValue;

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    byteBoolean hashAlgSpecified;
    TAP_HASH_ALG hashAlg;

    byteBoolean inPrivKeyFileSpecified;
    TAP_Buffer privKeyFile;

    byteBoolean inQualifyingDataFileSpecified;
    TAP_Buffer inQualifyingDataFile;

    byteBoolean outAttestationFileSpecified;
    TAP_Buffer outAttestationFile;

    byteBoolean outSignatureFileSpecified;
    TAP_Buffer outSignatureFile;

    byteBoolean pcrSpecified;
    ubyte4 numPcrs;
    ubyte pcrList[24];

    ubyte4 serverNameLen;
    ubyte4 serverPort;

#ifndef __ENABLE_TAP_REMOTE__ 
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif /* !__ENABLE_TAP_REMOTE__ */

    TAP_ModuleId moduleNum;

    byteBoolean outTextFileSpecified;
    TAP_Buffer outTextFile;

    byteBoolean isRawSig;

} cmdLineOpts;


/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("digicert_tpm2_getquote: Help Menu\n");
    LOG_MESSAGE("This tool generates a TPM quote (a hash of specified PCRs, and a signature of the hash) using a nonce provided in an input file.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [display command line options]");
    LOG_MESSAGE("                   Help menu\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[server name]");
    LOG_MESSAGE("                   Mandatory. Host on which TPM chip is located.  This can be 'localhost' or a\n"
                "                   remote host running a TAP server.\n");
    LOG_MESSAGE("           --p=[server port]");
    LOG_MESSAGE("                   Port on which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[TPM 2.0 configuration file]");
    LOG_MESSAGE("                   Path to TPM 2.0 module configuration file.\n");
#endif
    LOG_MESSAGE("           --modulenum=[module num]");
    LOG_MESSAGE("                   Specify the module num to use. If not provided, the first module found is used.\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   Password of the key to load.\n");
    LOG_MESSAGE("           --halg=[hash algorithm]");
    LOG_MESSAGE("                   (Mandatory) Hash algorithm (sha1, sha256, sha384, or sha512) for the hash of the TPM quote.\n");
    LOG_MESSAGE("           --tdidx=[PCR index]");
    LOG_MESSAGE("                   (Optional) PCR index to use. Multiple PCR indexes can be specified by repeating this option.\n");    
    LOG_MESSAGE("           --pri=[input private key file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the private key.\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the nonce (maximum of 32 bytes).\n");
    LOG_MESSAGE("           --odf=[output data file]");
    LOG_MESSAGE("                   (Mandatory) Output file to write the TPM quote to.\n");
    LOG_MESSAGE("           --osf=[output Signature file]");
    LOG_MESSAGE("                   Output file that contain a signature of the TPM quote.\n");
    LOG_MESSAGE("           --raw [output signature in raw form]\n");
    LOG_MESSAGE("           --otf=[output text file]");
    LOG_MESSAGE("                   (Optional) Output file to write the TPM quote to in readable text form.\n");
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
#ifdef __ENABLE_TAP_REMOTE__
            {"s", required_argument, NULL, 2},
            {"p", required_argument, NULL, 3},
#endif
            {"kpwd", required_argument, NULL, 4},
            {"halg", required_argument, NULL, 5},
            {"pri", required_argument, NULL, 7},
            {"idf", required_argument, NULL, 8},
            {"odf", required_argument, NULL, 9},
            {"osf", required_argument, NULL, 10},
            {"tdidx", required_argument, NULL, 11},
#ifndef __ENABLE_TAP_REMOTE__
            {"conf", required_argument, NULL, 13},
#endif
            {"modulenum", required_argument, NULL, 14},
            {"otf", required_argument, NULL, 15},
            {"raw", no_argument, NULL, 16},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult;
    ubyte4 currPcr = 0;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif

    if (!pOpts || !argv || (0 == argc))
    {
        TPM2_DEBUG_PRINT_1("Invalid parameters.");
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
#ifdef __ENABLE_TAP_REMOTE__
        case 2:
            pOpts->serverNameSpecified = TRUE;
            if (DIGI_STRLEN((const sbyte *)optarg) > SERVER_NAME_LEN)
            {
                LOG_ERROR("Server name too long. Max size: %d bytes",
                        SERVER_NAME_LEN);
                goto exit;
            }
            pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg) + 1;
            if ((pOpts->serverNameLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--s Server name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                    DIGI_STRLEN((const sbyte *)optarg)))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
            break;

        case 3:
            pOpts->serverPort = strtol(optarg, NULL, 0);
            if (pOpts->serverPort == 0)
            {
                LOG_ERROR("Invalid or no port number specified");
                goto exit;
            }

            if (pOpts->serverPort < 1 || pOpts->serverPort > 65535)
            {
                LOG_ERROR("Port number must be in the range 1-65535");
                goto exit;
            }

            TPM2_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
            break;
#endif

        case 4:
            /* --kpwd password */
            pOpts->keyAuthSpecified = TRUE;
            pOpts->keyAuthValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->keyAuthValue.pBuffer, 
                            pOpts->keyAuthValue.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for password",
                        (int)pOpts->keyAuthValue.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->keyAuthValue.pBuffer, optarg, 
                        pOpts->keyAuthValue.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Key password: %s", optarg); 

            break;

        case 5:
            /* --halg digest hash algorithm */
            pOpts->hashAlgSpecified = TRUE;

            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--halg Digest hash algorithm not specified");
                goto exit;
            }
            /* Check length of hash algorithm string */
            if(DIGI_STRLEN((const sbyte *)optarg) > DIGI_STRLEN((const sbyte *)"sha512"))
            {
                LOG_ERROR("--halg Invalid hash algorithm. Must be sha1, sha256, sha384, or sha512");
                goto exit;
            }

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha1",
                    DIGI_STRLEN((const sbyte *)"sha1"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA1;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA1");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha256",
                    DIGI_STRLEN((const sbyte *)"sha256"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA256;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA256");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha384",
                    DIGI_STRLEN((const sbyte *)"sha384"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA384;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA384");
                break;
            }

            cmpResult = 0;

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha512",
                    DIGI_STRLEN((const sbyte *)"sha512"), &cmpResult))
            {
                TPM2_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->hashAlg = TAP_HASH_ALG_SHA512;
                TPM2_DEBUG_PRINT_1("Setting Hash algorithm to SHA512");
                break;
            }
            LOG_ERROR("--kh not sha1 or sha256 or sha512");
            goto exit;

        case 7:
            /* --pri input private key file */
            pOpts->inPrivKeyFileSpecified = TRUE;
            pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->privKeyFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--pri Private key input file not specified");
                goto exit;
            }

            if (pOpts->privKeyFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Private key filename too long. Max size: %d bytes",
                        FILE_PATH_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->privKeyFile.pBuffer, 
                            pOpts->privKeyFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for Public key filename",
                        (int)pOpts->privKeyFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->privKeyFile.pBuffer, optarg, 
                        pOpts->privKeyFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);

            break;

        case 8:
            /* --idf input data file */
            pOpts->inQualifyingDataFileSpecified = TRUE;
            pOpts->inQualifyingDataFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->inQualifyingDataFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--idf Input data file not specified");
                goto exit;
            }

            if (pOpts->inQualifyingDataFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Input data filename too long. Max size: %d bytes",
                        FILE_PATH_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->inQualifyingDataFile.pBuffer, 
                            pOpts->inQualifyingDataFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for input data filename",
                        (int)pOpts->inQualifyingDataFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->inQualifyingDataFile.pBuffer, optarg, 
                        pOpts->inQualifyingDataFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Input data filename: %s", pOpts->inQualifyingDataFile.pBuffer);

            break;

        case 9:
            /* --odf output attestation file */
            pOpts->outAttestationFileSpecified = TRUE;
            pOpts->outAttestationFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->outAttestationFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--odf Output attestation file not specified");
                goto exit;
            }

            if (pOpts->outAttestationFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Attestation filename too long. Max size: %d bytes",
                        FILE_PATH_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->outAttestationFile.pBuffer, 
                            pOpts->outAttestationFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for attestation filename",
                        (int)pOpts->outAttestationFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->outAttestationFile.pBuffer, optarg, 
                        pOpts->outAttestationFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Attestation output filename: %s", pOpts->outAttestationFile.pBuffer);

            break;

        case 10:
            /* --osf output signature file */
            pOpts->outSignatureFileSpecified = TRUE;
            pOpts->outSignatureFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

            if ((pOpts->outSignatureFile.bufferLen == 1) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--osf Output signature file not specified");
                goto exit;
            }

            if (pOpts->outSignatureFile.bufferLen > FILE_PATH_LEN)
            {
                LOG_ERROR("Signature filename too long. Max size: %d bytes",
                        FILE_PATH_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->outSignatureFile.pBuffer, 
                            pOpts->outSignatureFile.bufferLen)))
            {
                LOG_ERROR("Unable to allocate %d bytes for signature filename",
                        (int)pOpts->outSignatureFile.bufferLen);
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->outSignatureFile.pBuffer, optarg, 
                        pOpts->outSignatureFile.bufferLen))
            {
                TPM2_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Signature output filename: %s", pOpts->outSignatureFile.pBuffer);

            break;

        case 11:
            currPcr = strtol(optarg, NULL, 0);
            if (currPcr > 23)
            {
                LOG_ERROR("Invalid PCR number specified");
                goto exit;
            }
            pOpts->pcrList[pOpts->numPcrs] = (ubyte)currPcr;
            TPM2_DEBUG_PRINT("PCR: %d", pOpts->pcrList[pOpts->numPcrs]);
            pOpts->numPcrs++;
            pOpts->pcrSpecified = TRUE ;

            break;

        case 13:
                /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
                pOpts->isConfFileSpecified = TRUE;
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                if (optValLen > FILE_PATH_LEN)
                {
                    LOG_ERROR("File path too long. Max size: %d bytes",
                            FILE_PATH_LEN);
                    goto exit;
                }
                if ((0 >= optValLen) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Configuration file path not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->confFilePath, optarg, optValLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("TPM2 Configuration file path: %s", 
                                 pOpts->confFilePath);
#else
                LOG_ERROR("TPM2 configuration file path not a "
                          "valid option in a local-only build\n");
                goto exit;
#endif
                break;
            case 14:
                pOpts->moduleNum = DIGI_ATOL((const sbyte *)optarg, NULL);
                if (0 >= pOpts->moduleNum)
                {
                    TPM2_DEBUG_PRINT_1("Invalid module num. Must be greater then 0");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("module num: %d", pOpts->moduleNum);
                break;

            case 15:
                /* --otf output text file */
                pOpts->outTextFileSpecified = TRUE;
                pOpts->outTextFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg) + 1;

                if ((pOpts->outTextFile.bufferLen == 1) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("--otf Output signature file not specified");
                    goto exit;
                }
                
                if (pOpts->outTextFile.bufferLen > FILE_PATH_LEN)
                {
                    LOG_ERROR("Signature filename too long. Max size: %d bytes",
                            FILE_PATH_LEN);
                    goto exit;
                }

                if (OK != (status = DIGI_MALLOC((void **)&pOpts->outTextFile.pBuffer,
                                pOpts->outTextFile.bufferLen)))
                {
                    LOG_ERROR("Unable to allocate %d bytes for signature filename",
                            (int)pOpts->outTextFile.bufferLen);
                    goto exit;
                }
                if (OK != DIGI_MEMCPY(pOpts->outTextFile.pBuffer, optarg,
                            pOpts->outTextFile.bufferLen))
                {
                    TPM2_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                TPM2_DEBUG_PRINT("Text output filename: %s", pOpts->outTextFile.pBuffer);

                break;
            case 16:
                TPM2_DEBUG_PRINT_1("raw signature: TRUE");
                pOpts->isRawSig = TRUE;
                break;
        default:
            goto exit;
        }
    }
    retval = 0;
exit:
    return retval;
}
#endif

static TAP_Module *getTapModule(TAP_ModuleList *pModuleList, TAP_ModuleId moduleNum)
{
    ubyte4 i;
    TAP_Module *pModule = NULL;

    if (NULL != pModuleList)
    {
        if (0 == moduleNum)
        {
            if (0 < pModuleList->numModules)
                pModule = &(pModuleList->pModuleList[0]);
        }
        else
        {
            for (i = 0; i < pModuleList->numModules; i++)
            {
                if (pModuleList->pModuleList[i].moduleId == moduleNum)
                {
                    pModule = &(pModuleList->pModuleList[i]);
                    break;
                }
            }
        }
    }
    return pModule;
}

static MSTATUS printQuote(TAP_Buffer *pOutFile, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status = OK;
    sbyte4 i = 0;
    ubyte *pPtr = pBuffer;
    ubyte4 len = 0;
    ubyte8 value = 0;

    ubyte pText[2048] = {0};
    ubyte *pTextPtr = (ubyte *) pText;
    ubyte4 textLen = 0;

    /* 4 byte magic */
    textLen = sprintf(pTextPtr,"magic: %02x%02x%02x%02x\n", pPtr[0], pPtr[1], pPtr[2], pPtr[3]);
    pPtr += 4;
    pTextPtr += textLen;

    /* 2 byte type*/
    textLen = sprintf(pTextPtr,"type: %02x%02x\n", pPtr[0], pPtr[1]);
    pPtr += 2;
    pTextPtr += textLen;

    /* 2 byte signer len */
    len = ((*pPtr) << 8) + *(pPtr + 1);
    pPtr += 2;

    /* signer */
    textLen = sprintf(pTextPtr, "qualifiedSigner: ");
    pTextPtr += textLen;
    for (i = 0; i < len; i++)
    {
        textLen = sprintf(pTextPtr, "%02x", pPtr[i]);
        pTextPtr += textLen;
    }
    textLen = sprintf(pTextPtr,"\n");
    pPtr += len;
    pTextPtr += textLen;

    /* 2 byte nonce len */
    len = ((*pPtr) << 8) + *(pPtr + 1);
    pPtr += 2;

    /* nonce */
    textLen = sprintf(pTextPtr, "extraData: ");
    pTextPtr += textLen;
    for (i = 0; i < len; i++)
    {
        textLen = sprintf(pTextPtr, "%02x", pPtr[i]);
        pTextPtr += textLen;
    }
    textLen = sprintf(pTextPtr,"\n");
    pPtr += len;
    pTextPtr += textLen;

    /* clock info */
    textLen = sprintf(pTextPtr,"clockInfo:\n");
    pTextPtr += textLen;
    value = ((ubyte8) pPtr[0] << 56) | ((ubyte8) pPtr[1] << 48) | ((ubyte8) pPtr[2] << 40) | ((ubyte8) pPtr[3] << 32) |
            ((ubyte8) pPtr[4] << 24) | ((ubyte8) pPtr[5] << 16) | ((ubyte8) pPtr[6] << 8) | (ubyte8) pPtr[7];
    textLen = sprintf(pTextPtr,"  clock: %lld\n", value);
    pPtr += 8;
    pTextPtr += textLen;

    value = ((ubyte8) pPtr[0] << 24) | ((ubyte8) pPtr[1] << 16) | ((ubyte8) pPtr[2] << 8) | (ubyte8) pPtr[3];
    textLen = sprintf(pTextPtr,"  resetCount: %d\n", (ubyte4) value);
    pPtr += 4;
    pTextPtr += textLen;

    value = ((ubyte8) pPtr[0] << 24) | ((ubyte8) pPtr[1] << 16) | ((ubyte8) pPtr[2] << 8) | (ubyte8) pPtr[3];
    textLen = sprintf(pTextPtr,"  restartCount: %d\n", (ubyte4) value);
    pPtr += 4;
    pTextPtr += textLen;

    textLen = sprintf(pTextPtr,"  safe: %d\n", *pPtr);
    pPtr += 1;
    pTextPtr += textLen;

    /* firmware version */
    textLen = sprintf(pTextPtr, "firmwareVersion: ");
    pTextPtr += textLen;
    for (i = 0; i < 8; i++)
    {
        textLen = sprintf(pTextPtr, "%02x", pPtr[i]);
        pTextPtr += textLen;
    }
    textLen = sprintf(pTextPtr,"\n");
    pPtr += 8;
    pTextPtr += textLen;

    /* attested */
    textLen = sprintf(pTextPtr,"attested:\n");
    pTextPtr += textLen;
    textLen = sprintf(pTextPtr,"  quote:\n");
    pTextPtr += textLen;
    textLen = sprintf(pTextPtr,"    pcrSelect:\n");
    pTextPtr += textLen;
    len = ((*pPtr) << 24) +  ((*(pPtr + 1)) << 16) + ((*(pPtr + 2)) << 8) + (*(pPtr + 3));
    textLen = sprintf(pTextPtr,"      count: %d\n", len);
    pPtr += 4;
    pTextPtr += textLen;
    textLen = sprintf(pTextPtr,"      pcrSelections:\n");
    pTextPtr += textLen;
    for (i = 0; i < len; i++)
    {
        textLen = sprintf(pTextPtr,"        %d:\n", *pPtr);
        pTextPtr += textLen;
        textLen = sprintf(pTextPtr,"          hash: %d\n", (ubyte4) pPtr[1]);
        pTextPtr += textLen;
        textLen = sprintf(pTextPtr,"          sizeofSelect: %d\n", (ubyte4) pPtr[2]);
        pTextPtr += textLen;
        textLen = sprintf(pTextPtr,"          pcrSelect: %02x%02x%02x\n", pPtr[3], pPtr[4], pPtr[5]);
        pPtr += 6;
        pTextPtr += textLen;
    }

    /* 2 byte nonce len */
    len = ((*pPtr) << 8) + *(pPtr + 1);
    pPtr += 2;

    /* hash */
    textLen = sprintf(pTextPtr,"    pcrDigest: ");
    pTextPtr += textLen;
    for (i = 0; i < len; i++)
    {
        textLen = sprintf(pTextPtr, "%02x", pPtr[i]);
        pTextPtr += textLen;
    }
    textLen = sprintf(pTextPtr,"\n");
    pTextPtr += textLen;

    textLen = (ubyte4) (pTextPtr - (ubyte *) pText);

    status = DIGICERT_writeFile((const char *)pOutFile->pBuffer, pText, textLen);
    if (OK != status)
    {
        LOG_ERROR("Error writing Quote text to file, status = %d\n", status);
    }

exit:

    return status;
}

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = ERR_GENERAL;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_ConfigInfoList configInfoList = { 0, };
#ifndef __ENABLE_TAP_REMOTE__
    char *pTpm2ConfigFile = NULL;
#endif
    ubyte tapInit = FALSE;
    ubyte gotModuleList = FALSE;
    ubyte contextInit = FALSE;
    ubyte *pBuffer = NULL;
    TAP_Buffer keyBlob = {0};
    TAP_Buffer qualifyingData = {0};
    TAP_Key *pLoadedTapKey = NULL;
    TAP_HASH_ALG hashAlg = 0;
    TAP_TRUSTED_DATA_TYPE dataType = TAP_TRUSTED_DATA_TYPE_MEASUREMENT;
    TAP_Blob attestationData = {0};
    TAP_TrustedDataInfo dataInfo = {0};
    TAP_Buffer pcrbuf = {0};
    TAP_Attribute attrList[2] = {0};
    TAP_Signature quoteSignature = { 0 };
    ubyte4 offset = 0;
    static ubyte signatureBuffer[MAX_CMD_BUFFER];

    if (!pOpts)
    {
        TPM2_DEBUG_PRINT_1("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto help_exit;
    }
#ifdef __ENABLE_TAP_REMOTE__
    if (!pOpts->serverNameSpecified)
    {
        /* If options are not specified in command line, check environment variables */
        TAP_UTILS_getServerInfo(pOpts->serverName, sizeof(pOpts->serverName), 
                &pOpts->serverNameLen, &pOpts->serverNameSpecified,
                &pOpts->serverPort);
    }

    if (!pOpts->serverNameSpecified ||  
            !pOpts->inPrivKeyFileSpecified || !pOpts->inQualifyingDataFileSpecified ||
            !pOpts->outAttestationFileSpecified || !pOpts->hashAlgSpecified)
    {
        LOG_ERROR("One or more mandatory options --s, --pri, --halg, --idf, --odf not specified.");
        goto exit;
    }
    /* If server port is not specified, and the destination is URL use default port */
    if ((!pOpts->serverPort) && 
            DIGI_STRNICMP((const sbyte *)pOpts->serverName, 
                (const sbyte *)"/dev", 4))
    {
        pOpts->serverPort = TAP_DEFAULT_SERVER_PORT;   
    }
#else
    if (!pOpts->inPrivKeyFileSpecified || !pOpts->inQualifyingDataFileSpecified ||
        !pOpts->outAttestationFileSpecified || !pOpts->hashAlgSpecified)
    {
        LOG_ERROR("One or more mandatory options --pri, --halg, --idf, --odf not specified.");
        goto exit;
    }
    
#endif


    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        LOG_ERROR("Failed to allocate memory, status = %d", status);
        goto exit;
    }

#ifndef __ENABLE_TAP_REMOTE__
    if (TRUE == pOpts->isConfFileSpecified)
    {
        pTpm2ConfigFile = pOpts->confFilePath;
    }
    else
    {
#if defined(__RTOS_WIN32__)
        status = TAP_UTILS_getWinConfigFilePath(&pTpm2ConfigFile, TPM2_CONFIGURATION_FILE);
        if (OK != status)
        {
            goto exit;
        }
#else
        pTpm2ConfigFile = TPM2_CONFIGURATION_FILE;
#endif
    }

    status = TAP_readConfigFile(pTpm2ConfigFile,
            &configInfoList.pConfig[0].configInfo,
            pOpts->isConfFileSpecified);
    if (OK != status)
    {
        LOG_ERROR("Failed to read config file, status = %d", status);
        goto exit;
    }
#endif

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;

    status = TAP_init(&configInfoList, &errContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_init", status);
        goto exit;
    }
    tapInit = TRUE;

#ifdef __ENABLE_TAP_REMOTE__
    /* Discover modules */
    connInfo.serverName.pBuffer = (ubyte *)pOpts->serverName;
    connInfo.serverName.bufferLen = pOpts->serverNameLen;
    connInfo.serverPort = pOpts->serverPort;
#endif

#ifdef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
                               &moduleList, &errContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
                               &moduleList, &errContext);
#endif
    if (OK != status)
    {
        PRINT_STATUS("TAP_getModuleList", status);
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == moduleList.numModules)
    {
        printf("No TPM2 modules found\n");
        goto exit;
    }

#ifndef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleCredentials(getTapModule(&moduleList, pOpts->moduleNum),
            pTpm2ConfigFile, pOpts->isConfFileSpecified,
            &pEntityCredentials,
            &errContext);

    if (OK != status)
    {
        PRINT_STATUS("Failed to get credentials from Credential configuration file", status);
        goto exit;
    }
#endif

    if ((0 != pOpts->keyAuthValue.bufferLen) && (NULL != pOpts->keyAuthValue.pBuffer))
    {
        status = DIGI_CALLOC((void **) &(keyCredentials.pCredentialList), 1, sizeof(TAP_Credential));
        if (OK != status)
        {
            LOG_ERROR("Failed to allocate memory; status %d", status);
            goto exit;
        }
        keyCredentials.numCredentials = 1;
        keyCredentials.pCredentialList[0].credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        keyCredentials.pCredentialList[0].credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        keyCredentials.pCredentialList[0].credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
        keyCredentials.pCredentialList[0].credentialData.bufferLen = pOpts->keyAuthValue.bufferLen;
        keyCredentials.pCredentialList[0].credentialData.pBuffer = pOpts->keyAuthValue.pBuffer;
        pKeyCredentials = &keyCredentials;
    }

    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(getTapModule(&moduleList, pOpts->moduleNum), pEntityCredentials,
                                NULL, &pTapContext, &errContext);
    if (OK != status)
    {
        PRINT_STATUS("TAP_initContext", status);
        goto exit;
    }
    contextInit = TRUE;

    /* TODO: Format input parameters */
    /* Read input data file */
    status = DIGICERT_readFile((const char *)pOpts->inQualifyingDataFile.pBuffer, &(qualifyingData.pBuffer), &(qualifyingData.bufferLen));
    if (OK == status)
    {
        if (SHA512_RESULT_SIZE < qualifyingData.bufferLen)
        {
            LOG_ERROR("Qualifying data size %d cannot exceed %d bytes", qualifyingData.bufferLen, SHA256_RESULT_SIZE);
            goto exit;
        }

        /* Invoke TAP API */
        /* Load Key object from file */
        /* Read input data file */
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
        status = DIGICERT_readFileEx((const char *)pOpts->privKeyFile.pBuffer, 
                &keyBlob.pBuffer, &keyBlob.bufferLen, TRUE);
#else
        status = DIGICERT_readFile((const char *)pOpts->privKeyFile.pBuffer, 
                &keyBlob.pBuffer, &keyBlob.bufferLen);
#endif
        if (OK == status)
        {
            /* Deserialize into TAPKey */
            status = TAP_deserializeKey(&keyBlob, &pLoadedTapKey, &errContext);
            if (OK != status)
            {
                PRINT_STATUS("TAP_deserializeKey", status);
                goto exit;
            }

            /* Load TAPKey */
            status = TAP_loadKey(pTapContext, pEntityCredentials, pLoadedTapKey, pKeyCredentials, NULL, &errContext);
            if (OK != status)
            {
                PRINT_STATUS("TAP_loadKey", status);
                goto exit;
            }

            dataInfo.subType = 1;

            if (pOpts->pcrSpecified)
            {
                pcrbuf.pBuffer = pOpts->pcrList;
                pcrbuf.bufferLen = pOpts->numPcrs;
            }
            else
            {
                pcrbuf.pBuffer = NULL; 
                pcrbuf.bufferLen = 0;
            }

            attrList[0].pStructOfType = &pcrbuf;
            attrList[0].type = TAP_ATTR_TRUSTED_DATA_KEY;
            attrList[0].length = sizeof(pcrbuf);

            if (pOpts->hashAlgSpecified)
            {
                hashAlg = pOpts->hashAlg;
                attrList[1].pStructOfType = &hashAlg;
                attrList[1].type = TAP_ATTR_HASH_ALG;
                attrList[1].length = sizeof(hashAlg);
            }

            dataInfo.attributes.listLen = pOpts->hashAlgSpecified ? 2 : 1;
            dataInfo.attributes.pAttributeList = (TAP_Attribute *) attrList;
            
            /* Quote */
            status = TAP_getQuote(pLoadedTapKey, NULL, dataType, &dataInfo, &qualifyingData,
                                    NULL, &attestationData, &quoteSignature, &errContext);

            if (OK != status)
            {
                PRINT_STATUS("TAP_getQuote", status);
                goto exit;
            }
            else
            {
                if (pOpts->outTextFileSpecified)
                {
                    status = printQuote(&pOpts->outTextFile, attestationData.blob.pBuffer, attestationData.blob.bufferLen);
                    if (OK != status)
                    {
                        PRINT_STATUS("printQuote", status);
                        goto exit;
                    }
                }
                /* Save attestation data to output file */
                status = DIGICERT_writeFile((const char *)pOpts->outAttestationFile.pBuffer,
                                            attestationData.blob.pBuffer, attestationData.blob.bufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Error writing Quote to file, status = %d\n", status);
                    goto exit;
                }

                if (pOpts->isRawSig)
                {
                    switch (pLoadedTapKey->keyData.keyAlgorithm)
                    {
                        case TAP_KEY_ALGORITHM_RSA:
                            status = DIGI_MEMCPY(signatureBuffer, quoteSignature.signature.rsaSignature.pSignature, quoteSignature.signature.rsaSignature.signatureLen);
                            if (OK != status)
                                goto exit;
                            
                            offset = quoteSignature.signature.rsaSignature.signatureLen;
                            break;

                        case TAP_KEY_ALGORITHM_ECC:
                        {
                            /* get the proper signature len in case padding is required */
                            ubyte4 elementLen = 0;
        
                            switch(pLoadedTapKey->keyData.algKeyInfo.eccInfo.curveId)
                            {
                                case TAP_ECC_CURVE_NIST_P192:
                                    elementLen = 24;
                                    break;
                                case TAP_ECC_CURVE_NIST_P224:
                                    elementLen = 28;
                                    break;
                                case TAP_ECC_CURVE_NIST_P256:
                                    elementLen = 32;
                                    break;
                                case TAP_ECC_CURVE_NIST_P384:
                                    elementLen = 48;
                                    break;
                                case TAP_ECC_CURVE_NIST_P521:
                                    elementLen = 66;
                                    break;
                                default:
                                    status = ERR_EC_UNSUPPORTED_CURVE;
                                    goto exit;
                            }

                            status = DIGI_MEMCPY(signatureBuffer + elementLen - quoteSignature.signature.eccSignature.rDataLen, 
                                                quoteSignature.signature.eccSignature.pRData, quoteSignature.signature.eccSignature.rDataLen);
                            if (OK != status)
                                goto exit;
                            
                            status = DIGI_MEMCPY(signatureBuffer + 2*elementLen - quoteSignature.signature.eccSignature.sDataLen, 
                                                quoteSignature.signature.eccSignature.pSData, quoteSignature.signature.eccSignature.sDataLen);
                            if (OK != status)
                                goto exit;

                            offset = 2*elementLen;
                            break;
                        }
                        default:
                            status = ERR_BAD_KEY_TYPE;
                            goto exit;
                    }
                }
                else
                {
                    /* Serialize signature */
                    offset = 0;
                    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Signature,
                                                    TAP_SD_IN, (void *)&quoteSignature, sizeof(quoteSignature),
                                                    signatureBuffer, sizeof(signatureBuffer), &offset);
                    if (OK != status)
                    {
                        PRINT_STATUS("TAP_SERIALIZE_serialize", status);
                        goto exit;
                    }
                }
                
                /* Save Signature to output file */
                status = DIGICERT_writeFile((const char *)pOpts->outSignatureFile.pBuffer,
                                            signatureBuffer, offset);
                if (OK != status)
                {
                    LOG_ERROR("Error writing signature to file, status = %d\n", status);
                    goto exit;
                }

                retval = 0;
            }
        }
        else
        {
            LOG_ERROR("Error reading private key file, status = %d\n", status);
            goto exit;
        }
    }
    else
    {
        LOG_ERROR("Error reading input qualifying data file, status = %d\n", status);
        DB_PRINT("Errno = %d", errno);
        goto exit;
    }

exit:
#if defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__)
    if ((NULL != pTpm2ConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pTpm2ConfigFile);
    }
#endif

    if (NULL != pLoadedTapKey)
    {
        /* Unload key object */
        status = TAP_unloadKey(pLoadedTapKey, &errContext);
        if (OK != status)
            PRINT_STATUS("TAP_unloadKey", status);
    
        /* Free Key */
        status = TAP_freeKey(&pLoadedTapKey);
        if (OK != status)
            PRINT_STATUS("TAP_keyFree", status);
    }

    if (NULL != keyBlob.pBuffer)
        DIGICERT_freeReadFile(&keyBlob.pBuffer);

    if (NULL != pBuffer)
        DIGICERT_freeReadFile(&pBuffer);

    status = TAP_freeSignature(&quoteSignature);
    if (OK != status)
        PRINT_STATUS("TAP_freeSignature", status);

    if(NULL != attestationData.blob.pBuffer)
    {
        status = TAP_UTILS_freeBlob(&attestationData);
        if(OK != status)
            PRINT_STATUS("TAP_UTILS_freeBlob",status);
    }

    if (NULL != pEntityCredentials)
    {
        status = TAP_UTILS_clearEntityCredentialList(pEntityCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearEntityCredentialList", status);
        DIGI_FREE((void **)&pEntityCredentials);
    }
    if (NULL != keyCredentials.pCredentialList)
    {
        status = TAP_UTILS_clearCredentialList(&keyCredentials);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_clearCredentialList", status);
    }

    /* Uninitialize context */
    if ((TRUE == contextInit) && (NULL != pTapContext))
    {
        status = TAP_uninitContext(&pTapContext, &errContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninitContext", status);
    }
    /* Uninitialize TAP */
    if (TRUE == tapInit)
    {
        status = TAP_uninit(&errContext);
        if (OK != status)
            PRINT_STATUS("TAP_uninit", status);
    }
    /* Free module list */
    if ((TRUE == gotModuleList) && (moduleList.pModuleList))
    {
        status = TAP_freeModuleList(&moduleList);
        if (OK != status)
            PRINT_STATUS("TAP_freeModuleList", status);
    }
    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeConfigInfoList", status);
    }

    if(qualifyingData.pBuffer)
        DIGI_FREE((void **)&(qualifyingData.pBuffer));

help_exit:

    return retval;
}

static void
freeOptions(cmdLineOpts *pOpts)
{
    if (pOpts)
    {
        if (pOpts->outSignatureFile.pBuffer)
            DIGI_FREE((void **)&pOpts->outSignatureFile.pBuffer);

        if (pOpts->outAttestationFile.pBuffer)
            DIGI_FREE((void **)&pOpts->outAttestationFile.pBuffer);

        if (pOpts->inQualifyingDataFile.pBuffer)
            DIGI_FREE((void **)&pOpts->inQualifyingDataFile.pBuffer);

        if (pOpts->privKeyFile.pBuffer)
            DIGI_FREE((void **)&pOpts->privKeyFile.pBuffer);

        if (pOpts->outTextFile.pBuffer)
            DIGI_FREE((void **)&pOpts->outTextFile.pBuffer);

        /* Don't free keyAuthValue ekAuthValue TAP_Buffers as they are freed by TAP_UTILS_clearCredentialList */
    }

    return;
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
        TPM2_DEBUG_PRINT_1("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts)))
    {
        TPM2_DEBUG_PRINT_1("Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    if (0 != platCmdLineParser(pOpts, argc, argv))
    {
        TPM2_DEBUG_PRINT_1("Failed to parse command line options.");
        goto exit;
    }

    if (0 != executeOptions(pOpts))
    {
        TPM2_DEBUG_PRINT_1("Failed to generate Quote.");
        goto exit;
    }
    else
        LOG_MESSAGE("Get quote executed successfully");

    retval = 0;
exit:
    if (pOpts)
    {
        freeOptions(pOpts);
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);
    }

    if (0 != retval)
        LOG_ERROR("*****digicert_tpm2_getquote failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

