/*
 * oldloadConfig.c
 *
 * IPsec configuration loader (legacy)
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../ipsec/script.h"
#include "../ipsec/ipsecconf.h"
#include "nf_ipsec.h"

#define STATIC          /* Defines to static later */

static ubyte  _initMocana = 0;
static sbyte4 ipsecFid    = -1;

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

STATIC void
/*************************************************************
 *    Function: ipqx_terminate
 * Description: Terminate and release all local resources
 *      excode: Program exit code
 *************************************************************/
ipqx_terminate(int excode)
{
    if (_initMocana)
    {
        DIGICERT_freeDigicert();
        _initMocana = 0;
    }
    exit(excode);
}

STATIC MSTATUS
/*************************************************************
 *    Function: ipqx_init
 * Description: .
 *************************************************************/
ipqx_init()
{
    int status = OK;

    if (0 > (status = DIGICERT_initDigicert()))
    {
        goto error;
    }

    if (0 > (status = DIGICERT_initLog(exampleLogFn)))
        goto error;

    _initMocana = 1;
    return OK;

  error:
    ipqx_terminate(1);
    /* So compiler does not complain */
    return -1;
}

int
main(int argc, char **argv)
{
    ubyte   *buffer = NULL;
    sbyte    *configFile  = NULL;
    ubyte4   fsize;
    MSTATUS status = OK;
#define MAX_CF_SIZE      (10000)

    if (argc < 2) {
        fprintf(stderr, "Usage: %s config_file\n", argv[0]);
        return -1;
    }

    configFile = argv[1];
    ipqx_init();

    status = DIGICERT_readFile(configFile, &buffer, &fsize);
    if (status != OK) {
        perror(configFile);
        goto exit;
    }
    if (OK > (status = IPSEC_ParseScript(buffer))) {
        fprintf(stderr, "Error parsing config script\n");
        goto exit;
    }

exit:
    free(buffer);
    ipqx_terminate(0);
}

static MSTATUS
/*************************************************************
 *    Function: sendIoCtl
 * Description: .
 *     command:
 *         arg:
 *************************************************************/
IPSEC_sendIoCtl(IpsIoctlCmd_e command, void *arg)
{
    MSTATUS       status = OK;

    if (0 > ipsecFid) {
        ipsecFid = open("/dev/moc_ipsec", O_RDWR);
    }
    if (0 > ipsecFid) {
        perror("Error opening moc_ipsec");
        status = -1;
        goto exit;
    }
    if (0 > (status = ioctl(ipsecFid, command, arg))) {
        status = OK;                    /* Hack for now */
        perror("Error sending ioctl to moc_ipsec");
        goto exit;
    }
exit:
    return status;
}

extern sbyte4
/*************************************************************
 *    Function: IPSEC_confAdd
 * Description: .
 *      axConf:
 *         num:
 *************************************************************/
IPSEC_confAdd(IPSECCONF axConf, sbyte4 num)
{
    MSTATUS         status = OK;
    ExtIpSecConf_t  ioBuf;

    memcpy(&ioBuf.conf, axConf,       sizeof(ioBuf.conf));
    memcpy(&ioBuf.sa,   axConf->pxSa, sizeof(ioBuf.sa));

    if (OK > IPSEC_sendIoCtl(IOC_ADD_CONF, &ioBuf)) {
        status = ERR_IPSEC;
        goto exit;
    }
exit:
    return status;
}

