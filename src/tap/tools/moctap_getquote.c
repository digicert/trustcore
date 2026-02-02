/**
 @file moctap_getquote.c

 @page moctap_getquote

 @ingroup tap_tools_commands

 @htmlonly
 <h1>NAME</h1>
 moctap_getquote -
 @endhtmlonly
 Generates a quote from hash of the input file using SE chip.

 # SYNOPSIS
 `moctap_getquote [options]`

 # DESCRIPTION
 <B>moctap_getquote</B> This tool generates a Security Module quote using a nonce provided in an input file, and data in the trusted data source.

@verbatim
    --h [option(s)]
        Display help for the specified option(s).
    --s=[TAP server name or module path]
        Mandatory option. Specify the server name such as localhost or remote.
        module path such as /dev/tpm0.
    --p=[TAP server port]
        Port at which the TAP server is listening.
    --pn=[provider name]
        Provider label for the Security Module.
    --mid=[module id]
        Specify the module ID to use.
    --kpwd=[key password]
        Password of the key to load.
    --halg=[hash algorithm];
        Hash algorithm (sha1, sha256, or sha512) to use to hash the PCR values. Mandatory for key type of General.
    --ss=[signing scheme]
        Signing scheme (PCKS1_5, PKCS1_5_SHA1, PSS_SHA1, PSS_SHA256, ECDSA_SHA1, or ECDSA_SHA256) to use to generate a signature of the quote.
    --pr=[input private key file]
        (Mandatory) Input file that contains the private key.
    --idf=[input data file]
        (Mandatory) Input file that contains the nonce (maximum of 32 bytes).
    --odf=[output data file]
        (Mandatory) Output file to write the quote to.
    --osf=[output signature file]
        Output file that contain a signature of the quote.
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
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../common/mprintf.h"
#include "../../common/vlong.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../../data_protection/file_protect.h"
#endif
#include "../tap_api.h"
#include "../tap_utils.h"
#include "../tap_serialize.h"
#include "../tap_serialize_smp.h"
#include "moctap_tools_utils.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif
#if defined (__RTOS_WIN32__)
#include "../../common/mcmdline.h"
#endif

#define SERVER_NAME_LEN 256
#define FILE_PATH_LEN   256
#define TAPTOOL_CREDFILE_NAME_LEN  256
#define MAX_CMD_BUFFER 4096
#define MAX_PCR_REGISTERS 64

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean keyAuthSpecified;
    TAP_Buffer keyAuthValue;

    byteBoolean prNameSpecified;
    tapProviderEntry *pTapProviderEntry;

    byteBoolean modIdSpecified;
    TAP_ModuleId  moduleId;

    byteBoolean credFileSpecified;
    char credFileName[TAPTOOL_CREDFILE_NAME_LEN];

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];

    byteBoolean pcrHashAlgSpecified;
    TAP_HASH_ALG pcrHashAlg;

    byteBoolean signSchemeSpecified; 
    TAP_SIG_SCHEME signScheme;    /* Includes the Hash algorithm */

    byteBoolean inPrivKeyFileSpecified;
    TAP_Buffer privKeyFile;

    byteBoolean inQualifyingDataFileSpecified;
    TAP_Buffer inQualifyingDataFile;

    byteBoolean outAttestationFileSpecified;
    TAP_Buffer outAttestationFile;

    byteBoolean outSignatureFileSpecified;
    TAP_Buffer outSignatureFile;

    byteBoolean inPCRSpecified;
    ubyte inPCRValues[MAX_PCR_REGISTERS];
    ubyte4 numPCRValues;

    ubyte4 serverNameLen;
    ubyte4 serverPort;

#ifndef __ENABLE_TAP_REMOTE__ 
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
#endif /* !__ENABLE_TAP_REMOTE__ */

} cmdLineOpts;

extern MSTATUS
MocTap_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen, 
      TAP_EntityCredentialList **pUsageCredentials) ;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("moctap_getquote: Help Menu\n");
    LOG_MESSAGE("This tool generates a Security Module quote using a nonce provided in an input file, and data in the trusted data source.");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h [option(s)]");
    LOG_MESSAGE("                   Display help for the specified option(s)\n");
#ifdef __ENABLE_TAP_REMOTE__
    LOG_MESSAGE("           --s=[TAP server name or module path]");
    LOG_MESSAGE("                   Mandatory option. Specify the server name such as localhost or\n"
            "                       module path such as /dev/tpm0.\n");
    LOG_MESSAGE("           --p=[TAP server port]");
    LOG_MESSAGE("                   Port at which the TAP server is listening.\n");
#else
    LOG_MESSAGE("           --conf=[Security Module configuration file]");
    LOG_MESSAGE("                   Path to Security Module configuration file.\n");
#endif
    LOG_MESSAGE("           --pn=[provider name]");
    LOG_MESSAGE("                   Provider label for the Security Module.\n");
    LOG_MESSAGE("           --mid=[module id]");
    LOG_MESSAGE("                   Specify the module ID to use.\n");
    LOG_MESSAGE("           --kpwd=[key password]");
    LOG_MESSAGE("                   Password of the key to load.\n");
    LOG_MESSAGE("           --halg=[hash algorithm]");
    LOG_MESSAGE("                   Hash algorithm (sha1, sha256, or sha512) to use to hash the PCR values.\n"
                "                   Mandatory for key type of General.\n");
    LOG_MESSAGE("           --ss=[signing scheme]");
    LOG_MESSAGE("                   Signing scheme (PCKS1_5, PKCS1_5_SHA1, PKCS1_5_DER, PSS_SHA1, PSS_SHA256, ECDSA_SHA1, or ECDSA_SHA256)\n"
                "                   to use to generate a signature of the quote.\n");
    LOG_MESSAGE("           --pri=[input private key file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the private key.\n");
    LOG_MESSAGE("           --idf=[input data file]");
    LOG_MESSAGE("                   (Mandatory) Input file that contains the nonce (maximum of 32 bytes).\n");
    LOG_MESSAGE("           --odf=[output data file]");
    LOG_MESSAGE("                   (Mandatory) Output file to write the quote to.\n");
    LOG_MESSAGE("           --osf=[output signature file]");
    LOG_MESSAGE("                   Output file that contain a signature of the quote.\n");
/* TODO: Remove when PCRs are passed in the quote request */
#ifdef USE_PCRS
    LOG_MESSAGE("           --tdidx=[PCR index]");
    LOG_MESSAGE("                   (Optional) PCR index to use. Multiple PCR indexes can be specified by repeating this option.\n");
#endif
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
            {"ss", required_argument, NULL, 6},
            {"pri", required_argument, NULL, 7},
            {"idf", required_argument, NULL, 8},
            {"odf", required_argument, NULL, 9},
            {"osf", required_argument, NULL, 10},
/* TODO: Remove when PCRs are passed in the quote request */
#ifdef USE_PCRS
            {"tdidx", required_argument, NULL, 11},
#endif
            {"pn", required_argument, NULL, 12},
            {"mid", required_argument, NULL, 13},
            {"cred", required_argument, NULL, 14},
            {"conf", required_argument, NULL, 15},
            {NULL, 0, NULL, 0},
    };
    MSTATUS status;
    sbyte4 cmpResult;
    sbyte4 filenameLen ;
    char *pTemp = NULL;
    ubyte4 currPcr = 0;
#ifndef __ENABLE_TAP_REMOTE__
    ubyte4 optValLen = 0;
#endif

    if (!pOpts || !argv || (0 == argc))
    {
        MOCTAP_DEBUG_PRINT_1("Invalid parameters.");
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
            pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->serverNameLen >= SERVER_NAME_LEN)
            {
                LOG_ERROR("Server name too long. Max length: %d characters",
                        SERVER_NAME_LEN - 1);
                goto exit;
            }
            if ((pOpts->serverNameLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-s Server name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                    pOpts->serverNameLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->serverName[pOpts->serverNameLen] = '\0';
            MOCTAP_DEBUG_PRINT("Provider Server/Module name: %s", pOpts->serverName);
            pOpts->serverNameSpecified = TRUE;
            break;

        case 3:
            {
                char *endptr;
                long port;
                errno = 0;
                port = strtol(optarg, &endptr, 10);
                if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || !IS_VALID_PORT(port))
                {
                    LOG_ERROR("Invalid port number. Must be between 1 and 65535");
                    goto exit;
                }
                pOpts->serverPort = (ubyte4)port;
                MOCTAP_DEBUG_PRINT("Server Port: %d", pOpts->serverPort);
            }
            break;
#endif

        case 4:
            /* --kpwd password */
            pOpts->keyAuthValue.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if ((pOpts->keyAuthValue.bufferLen == 0) || ('-' == optarg[0]))
            {
                LOG_ERROR("--kpwd Key password not specified");
                goto exit;
            }

            if (pOpts->keyAuthValue.bufferLen > MAX_PASSWORD_LEN)
            {
                LOG_ERROR("Key password too long. Max length: %d characters",
                        MAX_PASSWORD_LEN);
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->keyAuthValue.pBuffer, 
                            pOpts->keyAuthValue.bufferLen + 1)))
            {
                LOG_ERROR("Unable to allocate %d bytes for password",
                        (int)(pOpts->keyAuthValue.bufferLen + 1));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->keyAuthValue.pBuffer, optarg, 
                        pOpts->keyAuthValue.bufferLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                DIGI_FREE(&pOpts->keyAuthValue.pBuffer);
                pOpts->keyAuthValue.bufferLen = 0;
                goto exit;
            }
            pOpts->keyAuthValue.pBuffer[pOpts->keyAuthValue.bufferLen] = '\0';
            pOpts->keyAuthSpecified = TRUE;

            break;

        case 5:
            /* --halg digest hash algorithm */
            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-halg Digest hash algorithm not specified");
                goto exit;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha1",
                    DIGI_STRLEN((const sbyte *)"sha1"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->pcrHashAlg = TAP_HASH_ALG_SHA1;
                MOCTAP_DEBUG_PRINT_1("Setting Hash algorithm to SHA1");
                pOpts->pcrHashAlgSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha256",
                    DIGI_STRLEN((const sbyte *)"sha256"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->pcrHashAlg = TAP_HASH_ALG_SHA256;
                MOCTAP_DEBUG_PRINT_1("Setting Hash algorithm to SHA256");
                pOpts->pcrHashAlgSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"sha512",
                    DIGI_STRLEN((const sbyte *)"sha512"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }
            if (!cmpResult)
            {
                pOpts->pcrHashAlg = TAP_HASH_ALG_SHA512;
                MOCTAP_DEBUG_PRINT_1("Setting Hash algorithm to SHA512");
                pOpts->pcrHashAlgSpecified = TRUE;
                break;
            }

            LOG_ERROR("--halg not sha1 or sha256 or sha512");
            goto exit;
            break;

        case 6:
            /* --ss input signing scheme */
            cmpResult = 1;

            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-ss Input signing scheme not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"pkcs1_5",
                    DIGI_STRLEN((const sbyte *)"pkcs1_5"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->signScheme = TAP_SIG_SCHEME_PKCS1_5;
                MOCTAP_DEBUG_PRINT_1("Setting Signing scheme to PKCS1_5, Hash algorithm to SHA256");
                pOpts->signSchemeSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"pkcs1_5_sha1",
                    DIGI_STRLEN((const sbyte *)"pkcs1_5_sha1"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->signScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                MOCTAP_DEBUG_PRINT_1("Setting Signing scheme to PKCS1_5, Hash algorithm to SHA1");
                pOpts->signSchemeSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"pkcs1_5_der",
                    DIGI_STRLEN((const sbyte *)"pkcs1_5_der"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->signScheme = TAP_SIG_SCHEME_PKCS1_5_DER;
                MOCTAP_DEBUG_PRINT_1("Setting Signing scheme to PKCS1_5_DER");
                pOpts->signSchemeSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"pss_sha1",
                    DIGI_STRLEN((const sbyte *)"pss_sha1"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->signScheme = TAP_SIG_SCHEME_PSS_SHA1;
                MOCTAP_DEBUG_PRINT_1("Setting Signing scheme to PSS, Hash algorithm to SHA1");
                pOpts->signSchemeSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"pss_sha256",
                    DIGI_STRLEN((const sbyte *)"pss_sha256"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->signScheme = TAP_SIG_SCHEME_PSS_SHA256;
                MOCTAP_DEBUG_PRINT_1("Setting Signing scheme to PSS, Hash algorithm to SHA256");
                pOpts->signSchemeSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"ecdsa_sha1",
                    DIGI_STRLEN((const sbyte *)"ecdsa_sha1"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->signScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                MOCTAP_DEBUG_PRINT_1("Setting Signing scheme to ECDSA, Hash algorithm to SHA1");
                pOpts->signSchemeSpecified = TRUE;
                break;
            }

            cmpResult = 1;
            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)"ecdsa_sha256",
                    DIGI_STRLEN((const sbyte *)"ecdsa_sha256"), &cmpResult))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to compare memory");
                goto exit;
            }

            if (!cmpResult)
            {
                pOpts->signScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                MOCTAP_DEBUG_PRINT_1("Setting Signing scheme to ECDSA, Hash algorithm to SHA256");
                pOpts->signSchemeSpecified = TRUE;
                break;
            }

            LOG_ERROR("--ss not pkcs1_5 or pkcs1_5_sha1 or pkcs1_5_der or pss_sha1 or pss_sha256 or ecdsa_sha1 or ecdsa_sha256");
            goto exit;
            break;

        case 7:
            /* --pri input private key file */
            pOpts->privKeyFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if ((pOpts->privKeyFile.bufferLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-pr Private key input file not specified");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->privKeyFile.pBuffer, 
                            pOpts->privKeyFile.bufferLen + 1)))
            {
                LOG_ERROR("Unable to allocate %d bytes for Public key filename",
                        (int)(pOpts->privKeyFile.bufferLen + 1));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->privKeyFile.pBuffer, optarg, 
                        pOpts->privKeyFile.bufferLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                DIGI_FREE(&pOpts->privKeyFile.pBuffer);
                pOpts->privKeyFile.bufferLen = 0;
                goto exit;
            }
            pOpts->privKeyFile.pBuffer[pOpts->privKeyFile.bufferLen] = '\0';
            pOpts->privKeyFile.bufferLen++;
            MOCTAP_DEBUG_PRINT("Private key filename: %s", pOpts->privKeyFile.pBuffer);
            pOpts->inPrivKeyFileSpecified = TRUE;

            break;

        case 8:
            /* --idf input data file */
            pOpts->inQualifyingDataFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if ((pOpts->inQualifyingDataFile.bufferLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-idf Input data file not specified");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->inQualifyingDataFile.pBuffer, 
                            pOpts->inQualifyingDataFile.bufferLen + 1)))
            {
                LOG_ERROR("Unable to allocate %d bytes for input data filename",
                        (int)(pOpts->inQualifyingDataFile.bufferLen + 1));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->inQualifyingDataFile.pBuffer, optarg, 
                        pOpts->inQualifyingDataFile.bufferLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                DIGI_FREE(&pOpts->inQualifyingDataFile.pBuffer);
                pOpts->inQualifyingDataFile.bufferLen = 0;
                goto exit;
            }
            pOpts->inQualifyingDataFile.pBuffer[pOpts->inQualifyingDataFile.bufferLen] = '\0';
            pOpts->inQualifyingDataFile.bufferLen++;
            MOCTAP_DEBUG_PRINT("Input data filename: %s", pOpts->inQualifyingDataFile.pBuffer);
            pOpts->inQualifyingDataFileSpecified = TRUE;

            break;

        case 9:
            /* --odf output attestation file */
            pOpts->outAttestationFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if ((pOpts->outAttestationFile.bufferLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-odf Output attestation file not specified");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->outAttestationFile.pBuffer, 
                            pOpts->outAttestationFile.bufferLen + 1)))
            {
                LOG_ERROR("Unable to allocate %d bytes for attestation filename",
                        (int)(pOpts->outAttestationFile.bufferLen + 1));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->outAttestationFile.pBuffer, optarg, 
                        pOpts->outAttestationFile.bufferLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                DIGI_FREE(&pOpts->outAttestationFile.pBuffer);
                pOpts->outAttestationFile.bufferLen = 0;
                goto exit;
            }
            pOpts->outAttestationFile.pBuffer[pOpts->outAttestationFile.bufferLen] = '\0';
            pOpts->outAttestationFile.bufferLen++;
            MOCTAP_DEBUG_PRINT("Attestation output filename: %s", pOpts->outAttestationFile.pBuffer);
            pOpts->outAttestationFileSpecified = TRUE;

            break;

        case 10:
            /* --osf output signature file */
            pOpts->outSignatureFile.bufferLen = DIGI_STRLEN((const sbyte *)optarg);

            if ((pOpts->outSignatureFile.bufferLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-osf Output signature file not specified");
                goto exit;
            }

            if (OK != (status = DIGI_MALLOC((void **)&pOpts->outSignatureFile.pBuffer, 
                            pOpts->outSignatureFile.bufferLen + 1)))
            {
                LOG_ERROR("Unable to allocate %d bytes for signature filename",
                        (int)(pOpts->outSignatureFile.bufferLen + 1));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->outSignatureFile.pBuffer, optarg, 
                        pOpts->outSignatureFile.bufferLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                DIGI_FREE(&pOpts->outSignatureFile.pBuffer);
                pOpts->outSignatureFile.bufferLen = 0;
                goto exit;
            }
            pOpts->outSignatureFile.pBuffer[pOpts->outSignatureFile.bufferLen] = '\0';
            pOpts->outSignatureFile.bufferLen++;
            MOCTAP_DEBUG_PRINT("Signature output filename: %s", pOpts->outSignatureFile.pBuffer);
            pOpts->outSignatureFileSpecified = TRUE;

            break;

        case 11:
            /* PCR registers to use for the quote */
            {
                char *endptr;
                long pcr;
                if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                    ('-' == optarg[0]))
                {
                    LOG_ERROR("-tdidx index not specified");
                    goto exit;
                }
                errno = 0;
                pcr = strtol(optarg, &endptr, 10);
                if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (pcr < 0) || (pcr >= MAX_PCR_REGISTERS))
                {
                    LOG_ERROR("Invalid PCR number specified");
                    goto exit;
                }
                pOpts->inPCRValues[pOpts->numPCRValues] = (ubyte)pcr;
                MOCTAP_DEBUG_PRINT("PCR: %d",
                        pOpts->inPCRValues[pOpts->numPCRValues]);
                pOpts->numPCRValues++;
                pOpts->inPCRSpecified = TRUE;
            }

            break;

        case 12:
            /* --provider name */
            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--pn provider name not specified");
                goto exit;
            }
            status = getProviderFromName((const ubyte*)optarg,
                                            &(pOpts->pTapProviderEntry));
            if(OK != status)
            {
                LOG_ERROR("--pn not a known provider %s", optarg);
                goto exit;
            }
            pOpts->prNameSpecified = TRUE;
            break;

            case 13:
            /* --mid module id */
            {
                char *endptr;
                long moduleId;
                errno = 0;
                moduleId = strtol(optarg, &endptr, 0);
                if ((errno == ERANGE) || (endptr == optarg) || (*endptr != '\0') || (moduleId < 0))
                {
                    LOG_ERROR("Invalid module id specified");
                    goto exit;
                }
                pOpts->moduleId = (ubyte4)moduleId;
                MOCTAP_DEBUG_PRINT("module id: %d", pOpts->moduleId);
                pOpts->modIdSpecified = TRUE;
            }
            break;

        case 14:
            /* --cred credential file */
            filenameLen = DIGI_STRLEN((const sbyte *)optarg);
            if (filenameLen >= TAPTOOL_CREDFILE_NAME_LEN)
            {
                LOG_ERROR("credential file name too long. Max length: %d characters",
                        TAPTOOL_CREDFILE_NAME_LEN - 1);
                goto exit;
            }
            if ((filenameLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--cred credential file name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->credFileName, optarg, filenameLen))
            {
                MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                goto exit;
            }
            pOpts->credFileName[filenameLen] = '\0';
            MOCTAP_DEBUG_PRINT("cred file name name: %s", pOpts->credFileName);
            pOpts->credFileSpecified = TRUE;
            break;
        case 15:
                /* tpm2 config file path */
#ifndef __ENABLE_TAP_REMOTE__
                optValLen = DIGI_STRLEN((const sbyte *)optarg); 
                if (optValLen >= FILE_PATH_LEN)
                {
                    LOG_ERROR("File path too long. Max length: %d characters",
                            FILE_PATH_LEN - 1);
                    goto exit;
                }
                if ((0 >= optValLen) || ('-' == optarg[0]))
                {
                    LOG_ERROR("Configuration file path not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->confFilePath, optarg, optValLen))
                {
                    MOCTAP_DEBUG_PRINT_1("Failed to copy memory");
                    goto exit;
                }
                pOpts->confFilePath[optValLen] = '\0';
                MOCTAP_DEBUG_PRINT("Provider Configuration file path: %s", 
                                 pOpts->confFilePath);
                pOpts->isConfFileSpecified = TRUE;
#else
                LOG_ERROR("Provider configuration file path not a "
                          "valid option in a local-only build\n");
                goto exit;
#endif
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

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    MSTATUS status = ERR_GENERAL;
#ifndef __ENABLE_TAP_REMOTE__
    char *pSmpConfigFile = NULL;
#endif
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 }; 
#endif
    TAP_ModuleList moduleList = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    /*TAP_Buffer userCredBuf = {0} ;*/
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_CredentialList keyCredentials = { 0 };
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_ConfigInfoList configInfoList = { 0, };
    ubyte tapInit = FALSE;
    ubyte contextInit = FALSE;
    //ubyte4 bufferLen = 0;
    TAP_Buffer keyBlob = {0};
    TAP_Buffer qualifyingData = {0};
    TAP_Key *pLoadedTapKey = NULL;
    TAP_TRUSTED_DATA_TYPE dataType = TAP_TRUSTED_DATA_TYPE_MEASUREMENT;
    TAP_Blob attestationData = {0};
    TAP_TrustedDataInfo dataInfo = {0};
    TAP_Buffer pcrbuf = {0};
    TAP_Attribute pcr = {0} ;
    TAP_Signature quoteSignature = { 0 };
    ubyte4 offset = 0;
    static ubyte signatureBuffer[MAX_CMD_BUFFER];
    ubyte gotModuleList = FALSE;

    if (!pOpts)
    {
        MOCTAP_DEBUG_PRINT_1("Invalid parameter.");
        goto exit;
    }

    if (pOpts->exitAfterParse)
    {
        retval = 0;
        goto exit;
    }
#ifdef __ENABLE_TAP_REMOTE
    if (!pOpts->serverNameSpecified ||  
            !pOpts->inPrivKeyFileSpecified || !pOpts->inQualifyingDataFileSpecified ||
            !pOpts->outAttestationFileSpecified || !pOpts->prNameSpecified || 
            !pOpts->modIdSpecified) 
    {
        LOG_ERROR("One or more mandatory options --s, --pri, --idf, --odf, --pn, --mid not specified.");
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
        !pOpts->outAttestationFileSpecified || !pOpts->prNameSpecified || 
        !pOpts->modIdSpecified)
    {
        LOG_ERROR("One or more mandatory options --pri, --idf, --odf, --pn, --mid not specified.");
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
        pSmpConfigFile = pOpts->confFilePath;
    }
    else
    {
#if defined(__RTOS_WIN32__)
        status = TAP_UTILS_getWinConfigFilePath(&pSmpConfigFile, pOpts->pTapProviderEntry->configFilePath);
        if (OK != status)
        {
            goto exit;
        }
#else
        pSmpConfigFile = pOpts->pTapProviderEntry->configFilePath;
#endif
    }

    status = TAP_readConfigFile(pSmpConfigFile,
            &configInfoList.pConfig[0].configInfo,
            pOpts->isConfFileSpecified);
    if (OK != status)
    {
        LOG_ERROR("Failed to read config file, status = %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = pOpts->pTapProviderEntry->providerType;
#endif /* !__ENABLE_TAP_REMOTE__ */

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
    status = TAP_getModuleList(&connInfo, pOpts->pTapProviderEntry->providerType, NULL,
                               &moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, pOpts->pTapProviderEntry->providerType, NULL,
                               &moduleList, pErrContext);
#endif

    if (OK != status)
    {
        PRINT_STATUS("TAP_getModuleList", status);
        goto exit;
    }
    gotModuleList = TRUE;
    if (0 == moduleList.numModules)
    {
        LOG_ERROR("No Provider modules found\n");
        goto exit;
    }
#ifndef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleCredentials(&(moduleList.pModuleList[0]),
            pSmpConfigFile, pOpts->isConfFileSpecified,
            &pEntityCredentials,
            pErrContext);

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
        pOpts->keyAuthValue.pBuffer = NULL;
        pOpts->keyAuthValue.bufferLen = 0;
        pKeyCredentials = &keyCredentials;
    }

    /* Initialize context on first module */
    pTapContext = NULL;
    status = TAP_initContext(&(moduleList.pModuleList[0]), pEntityCredentials,
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
        if (SHA256_RESULT_SIZE < qualifyingData.bufferLen)
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

            /* Set PCR */
            if (TRUE == pOpts->inPCRSpecified)
            {
                pcrbuf.pBuffer = pOpts->inPCRValues;
                pcrbuf.bufferLen = pOpts->numPCRValues;
            }
            dataInfo.subType = 1;
            pcr.pStructOfType = &pcrbuf ;
            pcr.type = TAP_ATTR_TRUSTED_DATA_KEY;
            pcr.length = sizeof(pcrbuf);
            dataInfo.attributes.listLen = 1 ;
            dataInfo.attributes.pAttributeList = &pcr ;
            
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
                /* Save attestation data to output file */
                status = DIGICERT_writeFile((const char *)pOpts->outAttestationFile.pBuffer,
                                            attestationData.blob.pBuffer, attestationData.blob.bufferLen);
                if (OK != status)
                {
                    LOG_ERROR("Error writing Quote to file, status = %d\n", status);
                    goto exit;
                }

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
    if ((NULL != pSmpConfigFile)
        && (FALSE == pOpts->isConfFileSpecified)
        )
    {
        DIGI_FREE(&pSmpConfigFile);
    }
#endif /* defined(__RTOS_WIN32__) && !defined(__ENABLE_TAP_REMOTE__) */

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

    if (TAP_KEY_ALGORITHM_UNDEFINED != quoteSignature.keyAlgorithm)
    {
        status = TAP_freeSignature(&quoteSignature);
        if (OK != status)
            PRINT_STATUS("TAP_freeSignature", status);
    }

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
        DIGI_FREE((void **)&pEntityCredentials) ;
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

/*    if (NULL != userCredBuf.pBuffer)
        DIGICERT_freeReadFile(&userCredBuf.pBuffer);*/
    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            PRINT_STATUS("TAP_UTILS_freeConfigInfoList", status);
    }

    if(qualifyingData.pBuffer)
        DIGI_FREE((void **)&(qualifyingData.pBuffer));

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

        if (pOpts->keyAuthValue.pBuffer)
            shredMemory((ubyte **)&(pOpts->keyAuthValue.pBuffer), pOpts->keyAuthValue.bufferLen, TRUE);

        if (NULL != pOpts->pTapProviderEntry)
            freeTapProviderEntry(&pOpts->pTapProviderEntry);
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
        MOCTAP_DEBUG_PRINT_1("No command line parser available for this platform.");
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pOpts, 1, sizeof(cmdLineOpts)))
    {
        MOCTAP_DEBUG_PRINT_1("Failed to allocate memory for cmdLineOpts.");
        goto exit;
    }

    if (0 != platCmdLineParser(pOpts, argc, argv))
    {
        MOCTAP_DEBUG_PRINT_1("Failed to parse command line options.");
        goto exit;
    }

    if (0 != executeOptions(pOpts))
    {
        MOCTAP_DEBUG_PRINT_1("Failed to generate Quote.");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
    {
        freeOptions(pOpts);
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);
    }

    if (0 != retval)
        LOG_ERROR("*****moctap_getquote failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}

