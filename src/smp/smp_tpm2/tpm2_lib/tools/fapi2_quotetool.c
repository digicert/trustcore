/*
 * fapi2_quotetool.c
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
#include "../../../../common/mfmgmt.h"
#include "../fapi2/fapi2.h"
#include "../tap_serialize_tpm2.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
#include "errno.h"
#include "unistd.h"
#include "getopt.h"
#endif

#ifdef __RTOS_WIN32__
#include "../../../../common/mcmdline.h"
#endif

#define SERVER_NAME_LEN 256
#define DEFAULT_SERVER_NAME "/dev/tpm0"
#define DEFAULT_PCR_BIT_MASK 0xFFFFFF
#define DEFAULT_QUOTE_FILE "quote.bin"
#define DEFAULT_QUOTE_TXT_FILE "quote.txt"
#define DEFAULT_SIG_FILE "quotesig.bin"

#define TPM2_DEBUG_PRINT_NO_ARGS(fmt) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__);\
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

#define PRINT_TO_FILE(fmt, ...)\
    do {\
        LOG_MESSAGE(fmt, ##__VA_ARGS__);\
        if (OK != FMGMT_fprintf (pFile, fmt, ##__VA_ARGS__))\
        {\
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to write to text file");\
            goto exit;\
        }\
    }while (0)

typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean akHandleSpecified;
    ubyte4 akHandle;

    byteBoolean nonceSpecified;
    TPM2B_DATA nonce;

    byteBoolean pcrIndexesSpecified;
    ubyte4 pcrIndex;

    byteBoolean quoteFileSpecified;
    ubyte4 quoteFileLen;
    char quoteFileName[SERVER_NAME_LEN];
    char quoteTextFileName[SERVER_NAME_LEN];

    byteBoolean sigFileSpecified;
    ubyte4 sigFileLen;
    char sigFileName[SERVER_NAME_LEN];

    byteBoolean serverNameSpecified;
    char serverName[SERVER_NAME_LEN];
    ubyte4 serverNameLen;
    ubyte4 serverPort;

    byteBoolean akAuthSpecified;
    TPM2B_AUTH akAuthValue;

    /*
     * Internal/Test only
     */
    byteBoolean testCreateAkSpecified;
    TPMI_ALG_PUBLIC akKeyAlg;
    byteBoolean ehAuthSpecified;
    TPM2B_AUTH ehAuthValue;

    byteBoolean shAuthSpecified;
    TPM2B_AUTH shAuthValue;

} cmdLineOpts;

/*
 * Platform specific command line parsing.
 */
typedef int (*platformParseCmdLineOpts)(cmdLineOpts *pOpts, int argc, char *argv[]);

void printHelp()
{
    LOG_MESSAGE("fapi2_quote: Help Menu\n");
    LOG_MESSAGE("This tool uses the TPM2 FAPI directly to create a quote."
            " Use digicert_tpm2_quote if available. For use only for Demo purposes."
            " Signature Scheme and Hash algorithm used will be the same ones used during key creation.\n");

    LOG_MESSAGE("Options:");
    LOG_MESSAGE("           --h");
    LOG_MESSAGE("                   Help menu");
    LOG_MESSAGE("           --s=[TPM server name or module path]");
    LOG_MESSAGE("                   Specify the server name such as localhost or\n"
            "                       module path such as /dev/tpm0. If not specified, /dev/tpm0 will be used.");
    LOG_MESSAGE("           --p=[TPM server port]");
    LOG_MESSAGE("                   Port at which the TPM server is listening.");
    LOG_MESSAGE("           --ak=[AK handle]");
    LOG_MESSAGE("                   Mandatory. Handle for the primary Attestation key in HEX.\n"
                "                   The Attestation key must already have been created."
                "                   Must be in the range: 0x%x - 0x%x.",
                (unsigned int)FAPI2_RH_PERSISTENT_ENDORSEMENT_START + 1, (unsigned int)FAPI2_RH_PERSISTENT_ENDORSEMENT_END);
    LOG_MESSAGE("           --pwd=[AK Password]");
    LOG_MESSAGE("                   Password for the AK\n"
                "                   If not specified, the well know password will be used.");
    LOG_MESSAGE("           --pcr=[pcr bit mask]");
    LOG_MESSAGE("                   Bit mask of PCR's that need to be included. Upto 24 PCR's are supported.(0xFFFFFF)\n"
                "                   If not specified, a bit mask for all PCR's [0xFFFFFFFF] will be used.");
    LOG_MESSAGE("           --nonce=[nonce]");
    LOG_MESSAGE("                   Mandatory. Nonce to be signed with the Quote.\n"
                "                   The value provided will be directly used as a byte string.");
    LOG_MESSAGE("           --qfile=[quote file name]");
    LOG_MESSAGE("                   File name to use to dump the quoted data.\n"
                "                   If no file name is provided, quote.bin and quote.txt will be used.");
    LOG_MESSAGE("           --sigfile=[signature file name]");
    LOG_MESSAGE("                   File name to use to dump signature data.\n"
                "                   If no file name is provided, quotesig.bin will be used.");
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
            {"s", required_argument, NULL, 2},
            {"p", required_argument, NULL, 3},
            {"ak", required_argument, NULL, 4},
            {"pcr", required_argument, NULL, 5},
            {"nonce", required_argument, NULL, 6},
            {"qfile", required_argument, NULL, 7},
            {"sigfile", required_argument, NULL, 8},
            {"test", required_argument, NULL, 9},
            {"ehauth", required_argument, NULL, 10},
            {"pwd", required_argument, NULL, 11},
            {"shauth", required_argument, NULL, 12},
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
            if ( pOpts->serverNameLen >= SERVER_NAME_LEN)
            {
                LOG_ERROR("Server name too long. Max size: %d bytes",
                        SERVER_NAME_LEN - 1);
                goto exit;
            }
            if ((pOpts->serverNameLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-s Server name not specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->serverName, optarg, pOpts->serverNameLen))             
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->serverName[pOpts->serverNameLen] = '\0';
            TPM2_DEBUG_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
            break;
        case 3:
            if (('\0' == optarg[0]) || ('-' == optarg[0]))
            {
                LOG_ERROR("Invalid port number specified");
                goto exit;
            }
            pOpts->serverPort = strtoul(optarg, NULL, 0);
            if ((pOpts->serverPort == 0) || (pOpts->serverPort > 65535))
            {
                LOG_ERROR("Invalid port number. Must be 1-65535");
                goto exit;
            }
            TPM2_DEBUG_PRINT("Server Port: %u", pOpts->serverPort);
            break;

        case 4:
            pOpts->akHandleSpecified = TRUE;
            
            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--ak AK handle not specified");
                goto exit;
            }
            
            pOpts->akHandle = strtoul(optarg, NULL, 0);
            if ((pOpts->akHandle < (FAPI2_RH_PERSISTENT_ENDORSEMENT_START + 1)) ||
                    (pOpts->akHandle > (FAPI2_RH_PERSISTENT_ENDORSEMENT_END)))
            {
                LOG_ERROR("Invalid AK handle specified. --ak must be in the range 0x%x - 0x%x",
                        (unsigned int)FAPI2_RH_PERSISTENT_ENDORSEMENT_START + 1, (unsigned int)FAPI2_RH_PERSISTENT_ENDORSEMENT_END);
                goto exit;
            }

            TPM2_DEBUG_PRINT("AK handle: 0x%x", pOpts->akHandle);
            break;
        case 5:
            pOpts->pcrIndexesSpecified = TRUE;
            
            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("--pcr PCR bit mask not specified");
                goto exit;
            }
            
            pOpts->pcrIndex = strtoul(optarg, NULL, 0);
            if ((pOpts->pcrIndex == 0) || (pOpts->pcrIndex > 0xFFFFFF))
            {
                LOG_ERROR("Invalid PCR mask specified. --pcr cannot be greater than 0xFFFFFF");
                goto exit;
            }
            TPM2_DEBUG_PRINT("PCR bit mask: 0x%x", pOpts->pcrIndex);
            break;
        case 6:
            pOpts->nonceSpecified = TRUE;
            pOpts->nonce.size = DIGI_STRLEN((const sbyte *)optarg);
            if ((pOpts->nonce.size == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("-nonce Nonce not specified");
                goto exit;
            }

            if (pOpts->nonce.size > sizeof(pOpts->nonce.buffer))
            {
                LOG_ERROR("--nonce. Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->nonce.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->nonce.buffer, optarg, pOpts->nonce.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->nonce.buffer[pOpts->nonce.size] = '\0';
            TPM2_DEBUG_PRINT("Nonce: %s", pOpts->nonce.buffer);
            break;
        case 7:
            pOpts->quoteFileSpecified = TRUE;
            pOpts->quoteFileLen = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->quoteFileLen + 4 >= SERVER_NAME_LEN)
            {
                LOG_ERROR("quote file name too long. Max size: %d bytes",
                        SERVER_NAME_LEN - 5);
                goto exit;
            }
            if ((pOpts->quoteFileLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("No quote file name specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->quoteFileName, optarg, pOpts->quoteFileLen))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(&(pOpts->quoteFileName[pOpts->quoteFileLen]), ".bin", 4))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->quoteFileName[pOpts->quoteFileLen + 4] = '\0';

            if (OK != DIGI_MEMCPY(pOpts->quoteTextFileName, optarg, pOpts->quoteFileLen))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(&(pOpts->quoteTextFileName[pOpts->quoteFileLen]), ".txt", 4))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->quoteTextFileName[pOpts->quoteFileLen + 4] = '\0';

            TPM2_DEBUG_PRINT("Quote file name: %s %s", pOpts->quoteFileName, pOpts->quoteTextFileName);
            break;
        case 8:
            pOpts->sigFileSpecified = TRUE;
            pOpts->sigFileLen = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->sigFileLen >= SERVER_NAME_LEN)
            {
                LOG_ERROR("Signature file name too long. Max size: %d bytes",
                        SERVER_NAME_LEN - 1);
                goto exit;
            }
            if ((pOpts->sigFileLen == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("No signature file name specified");
                goto exit;
            }

            if (OK != DIGI_MEMCPY(pOpts->sigFileName, optarg, pOpts->sigFileLen))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->sigFileName[pOpts->sigFileLen] = '\0';
            TPM2_DEBUG_PRINT("Signature File name: %s", pOpts->sigFileName);
            break;
        case 9:
            pOpts->testCreateAkSpecified = TRUE;
            if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                ('-' == optarg[0]))
            {
                LOG_ERROR("No AK value specified");
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
                pOpts->akKeyAlg = TPM2_ALG_RSA;
                TPM2_DEBUG_PRINT_NO_ARGS("Creating TEST RSA AK");
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
                pOpts->akKeyAlg = TPM2_ALG_ECC;
                TPM2_DEBUG_PRINT_NO_ARGS("Creating TEST ECC AK");
                break;
            }

            TPM2_DEBUG_PRINT_NO_ARGS("--test not ecc or rsa");
            goto exit;
        case 10:
            pOpts->ehAuthSpecified = TRUE;
            pOpts->ehAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->ehAuthValue.size > sizeof(pOpts->ehAuthValue.buffer))
            {
                TPM2_DEBUG_PRINT("--ehauth Password Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->ehAuthValue.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->ehAuthValue.buffer, optarg, pOpts->ehAuthValue.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->ehAuthValue.buffer[pOpts->ehAuthValue.size] = '\0';
            TPM2_DEBUG_PRINT("EH password: %s", pOpts->ehAuthValue.buffer);
            break;
        case 11:
            pOpts->akAuthSpecified = TRUE;
            pOpts->akAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->akAuthValue.size > sizeof(pOpts->akAuthValue.buffer))
            {
                TPM2_DEBUG_PRINT("--pwd Password Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->akAuthValue.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->akAuthValue.buffer, optarg, pOpts->akAuthValue.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->akAuthValue.buffer[pOpts->akAuthValue.size] = '\0';
            TPM2_DEBUG_PRINT("AK password: %s", pOpts->akAuthValue.buffer);
            break;
        case 12:
            pOpts->shAuthSpecified = TRUE;
            pOpts->shAuthValue.size = DIGI_STRLEN((const sbyte *)optarg);
            if (pOpts->shAuthValue.size > sizeof(pOpts->shAuthValue.buffer))
            {
                TPM2_DEBUG_PRINT("--shauth Password Length too long. Max size: %u bytes",
                        (unsigned int)sizeof(pOpts->shAuthValue.buffer));
                goto exit;
            }
            if (OK != DIGI_MEMCPY(pOpts->shAuthValue.buffer, optarg, pOpts->shAuthValue.size))
            {
                TPM2_DEBUG_PRINT_NO_ARGS("Failed to copy memory");
                goto exit;
            }
            pOpts->shAuthValue.buffer[pOpts->shAuthValue.size] = '\0';
            TPM2_DEBUG_PRINT("SH password: %s", pOpts->shAuthValue.buffer);
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

MSTATUS dumpQuoteToTextFile(AttestationGetQuoteOut *pQuote, const char *pTxtFile)
{
    MSTATUS status = ERR_GENERAL;
    TPMS_ATTEST attestData = { 0 };
    ubyte4 offset = 0;
    int i = 0;
    TPMS_PCR_SELECTION *pPcrSelection = NULL;
    ubyte4 pcrSelectionBitMask = 0 ;
    FileDescriptor pFile = NULL;

    if (!pQuote || !pTxtFile)
    {
        status = ERR_NULL_POINTER;
        TPM2_DEBUG_PRINT_NO_ARGS("Invalid pointers");
        goto exit;
    }

    status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_TPMS_ATTEST, TAP_SD_OUT,
            pQuote->quoted.attestationData, pQuote->quoted.size,
            (ubyte *)&attestData, sizeof(attestData), &offset);
    if ((OK != status) || (offset != pQuote->quoted.size))
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to deserialize Quote structure");
        goto exit;
    }

    if (attestData.attested.quote.pcrSelect.count != 1)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Quote should be obtained only for 1 hash algorithm");
        goto exit;
    }

    status = FMGMT_fopen(pTxtFile, "wb", &pFile);
    if (OK != status)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to open file for quote text");
        goto exit;
    }

    PRINT_TO_FILE("\n**********START QUOTE***************\n");
    PRINT_TO_FILE("Magic: 0x%x\n", (unsigned int)attestData.magic);
    PRINT_TO_FILE("Type: 0x%x\n", attestData.type);

    PRINT_TO_FILE("Qualified Signer: 0x");
    for (i = 0; i < attestData.qualifiedSigner.size; i++)
        PRINT_TO_FILE("%x",attestData.qualifiedSigner.name[i]);

    PRINT_TO_FILE("\nNonce: 0x");
    for (i = 0; i < attestData.extraData.size; i++)
        PRINT_TO_FILE("%x",attestData.extraData.buffer[i]);

    PRINT_TO_FILE("\nClock Info:\n");
    PRINT_TO_FILE("\tIs Safe: %s\n", attestData.clockInfo.safe ? "Yes" : "No");
    PRINT_TO_FILE("\tPower on time(ms): %llu\n", attestData.clockInfo.clock);
    PRINT_TO_FILE("\tTPM Restart count: %d\n", (int)attestData.clockInfo.restartCount);
    PRINT_TO_FILE("\tTPM Reset count: %d\n", (int)attestData.clockInfo.resetCount);

    PRINT_TO_FILE("Firmware Version: 0x%llx", attestData.firmwareVersion);

    PRINT_TO_FILE("\n PCR Quote:\n");
    pPcrSelection = &(attestData.attested.quote.pcrSelect.pcrSelections[0]);
    for (i = 0; i < pPcrSelection->sizeofSelect; i++)
    {
        pcrSelectionBitMask |= pPcrSelection->pcrSelect[i] << (i * 8);
    }
    PRINT_TO_FILE("\tPCR BitMask: 0x%x\n", (unsigned int)pcrSelectionBitMask);
    PRINT_TO_FILE("PCR Digest: 0x");
    for (i = 0; i < attestData.attested.quote.pcrDigest.size; i++)
        PRINT_TO_FILE("%x",attestData.attested.quote.pcrDigest.name[i]);
    PRINT_TO_FILE("\n");
    status = OK;
exit:
    if (NULL != pFile)
    {
        FMGMT_fclose (&pFile);
    }
    return status;

}

int executeOptions(cmdLineOpts *pOpts)
{
    int retval = -1;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pCtx = NULL;
    ContextIsTpmProvisionedOut isTpmProvisioned = { 0 };
    ContextGetPrimaryObjectNameIn akGetHandleIn = { 0 };
    ContextGetPrimaryObjectNameOut akHandle = { 0 };
    ContextSetHierarchyAuthIn hierarchyAuth = { 0 };
    AttestationGetQuoteIn quoteIn = { 0 };
    AttestationGetQuoteOut quoteOut = { 0 };
    char *pQuoteFileName = NULL;
    char *pQuoteTxt = NULL;
    char *pSigFileName = NULL;
    ubyte *pSigBuffer = NULL;
    ubyte *pOrigSigBuffer = NULL;
    ubyte4 sigBufferSize = 0;
    MSTATUS status = ERR_GENERAL;
    AdminCreateAKIn akCreateIn = { 0 };
    ContextSetObjectAuthIn akAuth = { 0 };
    ContextFlushObjectIn flushIn = { 0 };

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

    if (!pOpts->akHandleSpecified || !pOpts->nonceSpecified)
    {
        LOG_ERROR("One of mandatory options: --ak, --nonce, not specified.");
        goto exit;
    }

    if (!pOpts->serverNameSpecified)
    {
        pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)DEFAULT_SERVER_NAME);
        DIGI_MEMCPY((void *)pOpts->serverName, DEFAULT_SERVER_NAME, pOpts->serverNameLen);
    }

    rc = FAPI2_CONTEXT_init(&pCtx, pOpts->serverNameLen,
            (ubyte *)pOpts->serverName, pOpts->serverPort, 3, NULL);
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

    if (!isTpmProvisioned.provisioned)
    {
        LOG_ERROR("TPM is not provisioned.");
        goto exit;
    }

    if (pOpts->testCreateAkSpecified)
    {
        if (!pOpts->ehAuthSpecified || !pOpts->shAuthSpecified)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Endorsement or Storage hierarchy AUth not specified for test options."
                    " Using empty authValues");
        }

        hierarchyAuth.endorsementAuth = pOpts->ehAuthValue;
        hierarchyAuth.ownerAuth = pOpts->shAuthValue;
        rc = FAPI2_CONTEXT_setHierarchyAuth(pCtx, &hierarchyAuth);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to set EH AUTH");
        }

        if (pOpts->akAuthSpecified)
            akCreateIn.AKAuth = pOpts->akAuthValue;

        akCreateIn.keyAlg = pOpts->akKeyAlg;
        akCreateIn.persistentHandle = pOpts->akHandle;
        if (TPM2_ALG_RSA == akCreateIn.keyAlg)
        {
            akCreateIn.keyInfo.rsaInfo.keySize = 2048;
            akCreateIn.keyInfo.rsaInfo.exponent = 0x10001;
            akCreateIn.keyInfo.rsaInfo.hashAlg = TPM2_ALG_SHA256;
            akCreateIn.keyInfo.rsaInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;
            akCreateIn.keyInfo.rsaInfo.scheme = TPM2_ALG_RSASSA;
        }
        else
        {
            akCreateIn.keyInfo.eccInfo.curveID = TPM2_ECC_NIST_P256;
            akCreateIn.keyInfo.eccInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;
            akCreateIn.keyInfo.eccInfo.scheme = TPM2_ALG_ECDSA;
        }

        rc = FAPI2_ADMIN_createAK(pCtx, &akCreateIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to create AK. Possibly created already.");
        }
    }

    akGetHandleIn.persistentHandle = pOpts->akHandle;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pCtx, &akGetHandleIn, &akHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to get handle to AK. Is AK created? rc = 0x%x", (unsigned int)rc);
        goto exit;
    }

    akAuth.objName = akHandle.objName;
    if (pOpts->akAuthSpecified)
        akAuth.objAuth = pOpts->akAuthValue;
    else
        akAuth.forceUseAuthValue = TRUE;

    rc = FAPI2_CONTEXT_setObjectAuth(pCtx, &akAuth);
    if (TSS2_RC_SUCCESS != rc)
    {
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to set AK auth");
        goto exit;
    }

    if (pOpts->pcrIndexesSpecified)
        quoteIn.pcrSelection = pOpts->pcrIndex;
    else
        quoteIn.pcrSelection = DEFAULT_PCR_BIT_MASK;

    quoteIn.qualifyingData = pOpts->nonce;
    quoteIn.quoteKey = akHandle.objName;

    rc = FAPI2_ATTESTATION_getQuote(pCtx, &quoteIn, &quoteOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        LOG_ERROR("Failed to getQuote. rc = 0x%x", (unsigned int)rc);
        goto exit;
    }

    if (pOpts->quoteFileSpecified)
    {
        pQuoteFileName = pOpts->quoteFileName;
        pQuoteTxt = pOpts->quoteTextFileName;
    }
    else
    {
        pQuoteFileName = DEFAULT_QUOTE_FILE;
        pQuoteTxt = DEFAULT_QUOTE_TXT_FILE;
    }

    status = DIGICERT_writeFile((const char *)pQuoteFileName,
            quoteOut.quoted.attestationData, quoteOut.quoted.size);
    if (OK != status)
    {
        LOG_ERROR("Error writing Quote to file, status = %d\n", status);
        goto exit;
    }

    status = dumpQuoteToTextFile(&quoteOut, pQuoteTxt);
    if (OK != status)
    {
        LOG_ERROR("Failed to dump quote to text file, status = %d\n", status);
        goto exit;
    }

    switch (quoteOut.keyAlg)
    {
    case TPM2_ALG_RSA:
        sigBufferSize = quoteOut.signature.rsaSignature.size + sizeof(quoteOut.signature.rsaSignature.size);
        status = DIGI_CALLOC((void **)&pSigBuffer, 1, sigBufferSize);
        if (OK != status)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed memory allocation.");
            goto exit;
        }
        pOrigSigBuffer = pSigBuffer;

        *((ubyte4 *)pSigBuffer) = quoteOut.signature.rsaSignature.size;
        pSigBuffer +=  sizeof(ubyte4);
        status = DIGI_MEMCPY(pSigBuffer,
                            quoteOut.signature.rsaSignature.buffer,
                            quoteOut.signature.rsaSignature.size);
        if (OK != status)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed memory copy.");
            goto exit;
        }
        break;
    case TPM2_ALG_ECC:
        sigBufferSize = (quoteOut.signature.eccSignature.signatureR.size +
                sizeof(quoteOut.signature.eccSignature.signatureR.size) +
                quoteOut.signature.eccSignature.signatureS.size +
                sizeof(quoteOut.signature.eccSignature.signatureS.size));

        status = DIGI_CALLOC((void **)&pSigBuffer, 1, sigBufferSize);
        if (OK != status)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed memory allocation.");
            goto exit;
        }
        pOrigSigBuffer = pSigBuffer;
        *((ubyte4 *)pSigBuffer) = quoteOut.signature.eccSignature.signatureR.size;
        pSigBuffer += sizeof(ubyte4);
        status = DIGI_MEMCPY(pSigBuffer,
                            quoteOut.signature.eccSignature.signatureR.buffer,
                            quoteOut.signature.eccSignature.signatureR.size);
        if (OK != status)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed memory copy.");
            goto exit;
        }

        pSigBuffer += quoteOut.signature.eccSignature.signatureS.size;
        *((ubyte4 *)pSigBuffer) = quoteOut.signature.eccSignature.signatureS.size;
        pSigBuffer += sizeof(ubyte4);
        status = DIGI_MEMCPY(pSigBuffer,
                quoteOut.signature.eccSignature.signatureS.buffer,
                quoteOut.signature.eccSignature.signatureS.size);
        if (OK != status)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed memory copy.");
            goto exit;
        }

        break;
    default:
        LOG_ERROR("Invalid signing algorithm. Unexpected.");
        goto exit;
    }

    if (pOpts->sigFileSpecified)
        pSigFileName = pOpts->sigFileName;
    else
        pSigFileName = DEFAULT_SIG_FILE;

    status = DIGICERT_writeFile((const char *)pSigFileName,
            pSigBuffer, sigBufferSize);
    if (OK != status)
    {
        LOG_ERROR("Error writing Signature to file, status = %d\n", status);
        goto exit;
    }

    retval = 0;

    if (0 == retval)
        LOG_MESSAGE("Successfully Computed Quote. See files: %s %s %s.",
                pQuoteFileName, pQuoteTxt, pSigFileName);
exit:
    if (pOrigSigBuffer)
        DIGI_FREE((void **)&pOrigSigBuffer);

    if (pCtx)
    {
        flushIn.objName = akHandle.objName;
        FAPI2_CONTEXT_flushObject(pCtx, &flushIn);

        rc = FAPI2_CONTEXT_uninit(&pCtx);
        if (TSS2_RC_SUCCESS != rc)
        {
            TPM2_DEBUG_PRINT_NO_ARGS("Failed to free FAPI2 context");
        }
    }
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
        TPM2_DEBUG_PRINT_NO_ARGS("Failed to get quote.");
        goto exit;
    }

    retval = 0;
exit:
    if (pOpts)
        shredMemory((ubyte **)&pOpts, sizeof(cmdLineOpts), TRUE);

    if (0 != retval)
        LOG_ERROR("*****fapi2 quote tool failed to complete successfully.*****");

    DIGICERT_freeDigicert();
    return retval;
}
