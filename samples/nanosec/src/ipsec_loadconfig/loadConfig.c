/*
 * loadConfig.c
 *
 * IPsec configuration loader
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
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "moptions.h"
#include "mtypes.h"
#include "mocana.h"
#include "hw_accel.h"
#include "merrors.h"
#include "debug_console.h"
#include "script.h"


/*------------------------------------------------------------------*/

#define STATIC          /* Defines to static later */

static ubyte  _initMocana = 0;


/*------------------------------------------------------------------*/

void
exampleLogFn(sbyte4 module, sbyte4 severity, sbyte * msg)
{
    sbyte *moduleStr;
    sbyte *severityStr;

    switch (module)
    {
    case MOCANA_MSS: moduleStr = (sbyte *)"MSS"; break;
    case MOCANA_SSH: moduleStr = (sbyte *)"SSH"; break;
    case MOCANA_SSL: moduleStr = (sbyte *)"SSL"; break;
    case MOCANA_IKE: moduleStr = (sbyte *)"IKE"; break;
    case MOCANA_EAP: moduleStr = (sbyte *)"EAP"; break;
    default:
        moduleStr = (sbyte *)"UNKNOWN MODULE";
        break;
    }

    switch (severity)
    {
    case LS_CRITICAL: severityStr = (sbyte *)"CRITICAL"; break;
    case LS_MAJOR:    severityStr = (sbyte *)"MAJOR";    break;
    case LS_MINOR:    severityStr = (sbyte *)"MINOR";    break;
    case LS_WARNING:  severityStr = (sbyte *)"WARNING";  break;
    case LS_INFO:     severityStr = (sbyte *)"INFO";     break;
    default:
        severityStr = (sbyte *)"UNKNOWN SEVERITY";
        break;
    }
    printf("LOG_OUTPUT: %s %s %s\n", moduleStr, severityStr, msg);
}


/*------------------------------------------------------------------*/
/*
 * Function: ipqx_terminate
 * Description: Terminate and release all local resources
 *      excode: Program exit code
 */

STATIC void
ipqx_terminate(int excode)
{
    if (_initMocana)
    {
        /* DIGICERT_freeDigicert(); */
        _initMocana = 0;
    }
    exit(excode);
}


/*------------------------------------------------------------------*/
/*
 *    Function: ipqx_init
 * Description: .
 */

STATIC MSTATUS
ipqx_init()
{
    int status = OK;

/*
    if (0 > (status = DIGICERT_initDigicert()))
    {
        goto error;
    }
*/

    if (0 > (status = DIGICERT_initLog(exampleLogFn)))
        goto error;

    _initMocana = 1;
    return OK;

error:
    ipqx_terminate(1);
    /* So compiler does not complain */
    return -1;
}


/*------------------------------------------------------------------*/

static sbyte4
loadConfFile(sbyte *configFile)
{
    MSTATUS status;
    ubyte   *buffer;
    ubyte4  fsize;

    if (NULL == configFile)
        return -1;

    status = DIGICERT_readFile((char*)configFile, &buffer, &fsize);

    if (status != OK)
    {
        perror(configFile);
        return status;
    }

    buffer[fsize] = (ubyte)0;

    if (OK > (status = IPSEC_ParseScript(buffer,0, NULL)))
    {
        fprintf(stderr, "Error parsing config script: %d\n", status);
    }

    free(buffer);

    return status;
}


/*------------------------------------------------------------------*/

void
printUsage(char *command)
{
    fprintf(stderr, "Usage: %s <options>\n", command);
#ifdef __RTOS_QNX__
    fprintf(stderr,
            "\t-f <file>\n\t\tload configuration file\n"
            "\t-F\n\t\tflush sa\n"
            "\t-FP\n\t\tflush spd\n"
            "\t-d\n\t\tdump sa\n"
            "\t-dP\n\t\tdump spd\n"
            );

#else
    fprintf(stderr, \
            "\t-f <file>\n\t\tload configuration file\n" \
            "\t-F\n\t\tflush sa\n" \
            "\t-FP\n\t\tflush spd\n" \
            "\t-d\n\t\tdump sa\n" \
            "\t-dP\n\t\tdump spd\n" \
            );
#endif
#ifdef __ENABLE_DIGICERT_MISSIU__
    /* missiu runs one instance of the digicert ipsec stack per interface */
    fprintf(stderr, "\t-i <iface>\n" \
            "\t\tnetwork interface on which missiu is running.\n"
            "\t\tif only one instance is running, this option\n"
            "\t\tmay be omitted.\n");
#endif
}


/*------------------------------------------------------------------*/

extern sbyte4 dumpSpd(ubyte4 address);
extern sbyte4 dumpSa(ubyte4 address);
extern sbyte4 IPSEC_confFlush(void);
extern sbyte4 IPSEC_keyFlush(void);
#ifdef __ENABLE_DIGICERT_MISSIU__
extern void IPSEC_setInterface(char *arg);
#endif

/*------------------------------------------------------------------*/

#define MAX_CF_SIZE      (10000)
#define ERR_USAGE        (-2)

#if defined(__OSE_RTOS__)
extern sbyte4
startMocanaExample(sbyte4 argc, char *argv[])
#else
int
main(int argc, char **argv)
#endif
{
    MSTATUS    status = ERR_USAGE;
    intBoolean isPolicy = 0;
    char*      options;
    char*      configFile;
    char       c, cmd = -1;
    int        optind = 1;

    if (argc < 2)
        goto exit;

    while (optind < argc)
    {
        options = argv[optind];

        if ('-' != *options)
            goto exit;

        c = *(++options);

        if ('h' == c)
            goto exit;

        if (('d' == c) || ('F' == c))
        {
            if ('P' == *(++options))
                isPolicy = 1;
            cmd = c;
            optind++;
        }
        else if ('f' == c)
        {
            if (optind + 1 >= argc)
            {
                fprintf(stderr, "-f requires file argument\n");
                goto exit;
            }
            configFile = argv[optind + 1];
            optind += 2;
            cmd = c;
        }
#ifdef __ENABLE_DIGICERT_MISSIU__
        else if ('i' == c)
        {
            if (optind + 1 >= argc)
            {
                fprintf(stderr, "-i requires interface argument\n", c);
                goto exit;
            }
            IPSEC_setInterface(argv[optind + 1]);
            optind += 2;
        }
#endif
        else
        {
            fprintf(stderr, "unknown option: -%c\n", c);
            goto exit;
        }
    }

    ipqx_init();

    switch (cmd)
    {
    case 'F':
    {
        if (isPolicy)
            status = IPSEC_confFlush();
        else
            status = IPSEC_keyFlush();
        break;
    }
    case 'f':
        /*IPSEC_keyFlush();*/ /* flush; */
        /*IPSEC_confFlush();*/ /* spdflush; */
        status = loadConfFile(configFile);
        break;
    case 'd':
    {
        if (isPolicy)
            status = dumpSpd(0);
        else
            status = dumpSa(0);
        break;
    }
    default:
        status = ERR_USAGE;
        break;
    }

    ipqx_terminate(0);

exit:
    if (ERR_USAGE == status)
        printUsage(argv[0]);

    return 0;
}

