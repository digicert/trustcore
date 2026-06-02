/*
 * loadConfig_qnx.c
 *
 * QNX platform IPsec configuration loader
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

#ifdef __RTOS_QNX__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/neutrino.h>
#include <process.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <devctl.h>

#include "../../common/moptions.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/debug_console.h"

#include "../../ipsec/ipsec.h"
#include "../../ipsec/ipseckey.h"
#include "../../ipsec/ipsecconf.h"

#include "../../ike/ike.h"
#include "../../ike/ike_event.h"

#include "../../examples/ipsec/qnx/qnx_ipsec.h"

#ifdef __ENABLE_DIGICERT_IPV6__
#error "Must not define __ENABLE_DIGICERT_IPV6__"
#endif


/*------------------------------------------------------------------*/

static sbyte4 ipsecFid    = -1;
static sbyte4 IPSEC_sendIoCtl(IpsIoctlCmd_e command, void *arg, int argSize);


/*------------------------------------------------------------------*/

extern sbyte4
dumpSpd(ubyte4 address)
{
    sbyte4  value = (sbyte4)address;

    return IPSEC_sendIoCtl(IOC_DUMP_SPD, &value, sizeof(value));
}


/*------------------------------------------------------------------*/

extern sbyte4
dumpSa(ubyte4 address)
{
    sbyte4  value = (sbyte4)address;

    return IPSEC_sendIoCtl(IOC_DUMP_SA, &value, sizeof(value));
}


/*------------------------------------------------------------------*/

static sbyte4
flushData(sbyte4 id)
{
    sbyte4  value = 0;

    return IPSEC_sendIoCtl(id, &value, sizeof(value));
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confFlush(void)
{
    return flushData(IOC_FLUSH_SPD);
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyFlush(void)
{
    return flushData(IOC_FLUSH_SA);
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confAdd1(IPSECCONF pxConf)
{
    MSTATUS         status = OK;
    ExtIpSecConf_t  ioBuf;

    memcpy(&ioBuf.conf, pxConf,       sizeof(ioBuf.conf));
    memcpy(&ioBuf.sa,   pxConf->pxSa, sizeof(ioBuf.sa));
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    ioBuf.conf.isGdoi = pxConf->isGdoi;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    ioBuf.conf.isUnicastGDOI = pxConf->isUnicastGDOI;
#endif

    status = IPSEC_sendIoCtl(IOC_ADD_CONF, &ioBuf, sizeof(ioBuf));

    pxConf->index = ioBuf.conf.index;

    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyAdd(IPSECKEY pxKey, sbyte4 num)
{
    sbyte4 status = 0;

    sbyte4 i;
    for (i = 0; i < num; i++)
    {
        IPSECKEY pxKeyTmp = pxKey + i;

        ExtIpSecKey_t ioBuf;
        memcpy(&ioBuf.key, pxKeyTmp, sizeof(ioBuf.key));

        if (pxKeyTmp->pAuthKey)
            memcpy(ioBuf.authKey, pxKeyTmp->pAuthKey, pxKeyTmp->wAuthKeyLen);
        if (pxKeyTmp->pEncrKey)
            memcpy(ioBuf.encrKey, pxKeyTmp->pEncrKey, pxKeyTmp->wEncrKeyLen);

        status = IPSEC_sendIoCtl(IOC_ADD_KEY, &ioBuf, sizeof(ioBuf));

        if (1 > status)
        {
            if (0 > status) pxKeyTmp->status = status;
            else pxKeyTmp->status = ioBuf.key.status;
            break;
        }
    }

    if (i || (0 <= status)) /* !!! */
    status = i;

    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
IPSEC_sendIoCtl(IpsIoctlCmd_e command, void *arg, int argSize)
{
    sbyte4 status = 0;

    if (0 > ipsecFid)
    {
        ipsecFid = open("/moc_ipsec", O_RDWR);
    }

    if (0 > ipsecFid)
    {
        perror("Error opening moc_ipsec");
        status = -1;
        goto exit;
    }

    if (0 != devctl(ipsecFid, command, arg, argSize, &status))
    {
        perror("Error sending devctl to moc_ipsec");
        status = -1;
    }

    close(ipsecFid);
    ipsecFid = -1;

exit:
    return status;
}


#endif /* __RTOS_QNX__ */

