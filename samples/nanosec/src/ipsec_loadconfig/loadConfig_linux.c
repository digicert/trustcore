/*
 * loadConfig_linux.c
 *
 * Linux platform IPsec configuration loader
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

#if defined(__RTOS_LINUX__) || defined(__RTOS_ANDROID__)

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <unistd.h> /* for close() */
#include <stdint.h> /* for uintptr_t */

#include "moptions.h"

#include "mtypes.h"
#include "mocana.h"
#include "hw_accel.h"

#include "mdefs.h"
#include "merrors.h"
#include "debug_console.h"

#include "ipsec.h"
#include "ipsec_defs.h"
#include "ipsecconf.h"
#include "ipseckey.h"
#include "spd.h"
#include "ipsec_utils.h"

#include "mrtos.h"
#include "linux/gpl/nf_ipsec.h"

#ifdef LOADCONFIG_DUMP_TO_STDOUT
#ifdef __ENABLE_DIGICERT_IPV6__
#include "mstdlib.h"
#endif
#ifdef __ENABLE_IPSEC_ESN__
#include "int64.h"
#endif
#include "sadb.h"
#include "ipsec_protos.h"

#include "ipsec_crypto.h"
#include "utils.inc"
#endif /* LOADCONFIG_DUMP_TO_STDOUT */


/*------------------------------------------------------------------*/
/* Helper function to prepare ExtIpSecConf_t to send to ioctl.  This is used
 * by both the missiu and the in-kernel builds.
 */
extern sbyte4
IPSEC_confPrepare1(IPSECCONF pxConf, ExtIpSecConf_t *ioBuf)
{
    memcpy(&ioBuf->conf, pxConf,       sizeof(ioBuf->conf));
    memcpy(&ioBuf->sa,   pxConf->pxSa, sizeof(ioBuf->sa));

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SP_FLAG_IP6 & pxConf->flags)
    {
        if (pxConf->dwSrcIP)
            memcpy(ioBuf->srcIP,    (ubyte *)(uintptr_t)(pxConf->dwSrcIP),    16);
        if (pxConf->dwSrcIPEnd)
            memcpy(ioBuf->srcIPend, (ubyte *)(uintptr_t)(pxConf->dwSrcIPEnd), 16);
        if (pxConf->dwDestIP)
            memcpy(ioBuf->dstIP,    (ubyte *)(uintptr_t)(pxConf->dwDestIP),    16);
        if (pxConf->dwDestIPEnd)
            memcpy(ioBuf->dstIPend, (ubyte *)(uintptr_t)(pxConf->dwDestIPEnd), 16);
    }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_SP_FLAG_IP6_TUNNEL & pxConf->flags)
    {
        if (pxConf->dwTunlDestIP)
            memcpy(ioBuf->tunDstIP, (ubyte *)(uintptr_t)(pxConf->dwTunlDestIP), 16);
        if (pxConf->dwTunlSrcIP)
            memcpy(ioBuf->tunSrcIP, (ubyte *)(uintptr_t)(pxConf->dwTunlSrcIP),  16);
    }
#endif
#endif /* __ENABLE_DIGICERT_IPV6__ */
    return OK;
}

/* Helper function to prepare ExtIpSecKey_t to send to ioctl.  This is used
 * by both the missiu and the in-kernel builds.
 */
extern sbyte4
IPSEC_keyPrepare(IPSECKEY pxKey, ExtIpSecKey_t *ioBuf)
{
        memcpy(&ioBuf->key, pxKey, sizeof(ioBuf->key));

        if (pxKey->pAuthKey)
            memcpy(ioBuf->authKey, pxKey->pAuthKey, pxKey->wAuthKeyLen);
        if (pxKey->pEncrKey)
            memcpy(ioBuf->encrKey, pxKey->pEncrKey, pxKey->wEncrKeyLen);

#ifdef __ENABLE_DIGICERT_IPV6__
        if (IPSEC_SA_FLAG_IP6 & pxKey->flags)
        {
            if (pxKey->dwDestAddr)
                memcpy(ioBuf->dstAddr, (ubyte *)(uintptr_t)(pxKey->dwDestAddr), 16);
            if (pxKey->dwSrcAddr)
                memcpy(ioBuf->srcAddr, (ubyte *)(uintptr_t)(pxKey->dwSrcAddr), 16);
        }
#endif
        return OK;
}

#if !defined(__ENABLE_DIGICERT_MISSIU__)

/*------------------------------------------------------------------*/

static sbyte4 ipsecFid    = -1;
static sbyte4 IPSEC_sendIoCtl(IpsIoctlCmd_e command, void *arg, int argSize);


/*------------------------------------------------------------------*/

#if !defined(LOADCONFIG_DUMP_TO_STDOUT)
extern sbyte4
dumpSpd(ubyte4 address)
{
    sbyte4  value = (sbyte4)address;

    return IPSEC_sendIoCtl(IOC_DUMP_SPD, &value, sizeof(value));
}

#else

extern sbyte4
dumpSpd(ubyte4 address)
{
    MSTATUS         status = OK;
    ExtIpSecDump_t  *ioBuf = NULL;
    SPD             pSpd;
    ubyte4          i;
    sbyte4          index = 0;
    sbyte4          mirrored = 0;

    ubyte4 bufLen = 2 * IPSEC_SPD_MAX * sizeof(struct spd);
    ubyte4 ioBufSize = sizeof(ExtIpSecDump_t) + bufLen;
    if (NULL == (ioBuf = (ExtIpSecDump_t  *) malloc(ioBufSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    ioBuf->ip = address;
    ioBuf->bufLen = bufLen;
    memset(ioBuf->pBuf, 0x00, bufLen);

    if (OK > IPSEC_sendIoCtl(IOC_DUMP_SPD, ioBuf, ioBufSize))
    {
        status = ERR_IPSEC;
        goto exit;
    }

    pSpd = (SPD) ioBuf->pBuf;

    for (i=0; i < 2 * IPSEC_SPD_MAX; i++, pSpd++)
    {
        if (OK > print_spd(pSpd, &index, &mirrored))
            break;
    }

exit:
    if (NULL != ioBuf)
        free(ioBuf);

    return status;
}
#endif /* !defined(LOADCONFIG_DUMP_TO_STDOUT) */


/*------------------------------------------------------------------*/

#if !defined(LOADCONFIG_DUMP_TO_STDOUT)
extern sbyte4
dumpSa(ubyte4 address)
{
    sbyte4  value = (sbyte4)address;

    return IPSEC_sendIoCtl(IOC_DUMP_SA, &value, sizeof(value));
}

#else

extern sbyte4
dumpSa(ubyte4 address)
{
    MSTATUS         status = OK;
    ExtIpSecDump_t  *ioBuf = NULL;
    ubyte4          i;
    ubyte*          pSaBuf;
    SADB            pxSa;
    ubyte4          sadbSize = 0;
    ubyte4          bufLen, ioBufSize;

    if ((OK > IPSEC_sendIoCtl(IOC_GET_SADB_SIZE, &sadbSize, sizeof(sadbSize))) ||
        (0 == sadbSize))
    {
        status = ERR_IPSEC;
        goto exit;
    }

    bufLen = IPSEC_SADB_MAX * sadbSize;
    ioBufSize = sizeof(ExtIpSecDump_t) + bufLen;
    if (NULL == (ioBuf = (ExtIpSecDump_t  *) malloc(ioBufSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    ioBuf->ip = address;
    ioBuf->bufLen = bufLen;
    memset(ioBuf->pBuf, 0x00, bufLen);

    if (OK > IPSEC_sendIoCtl(IOC_DUMP_SA, ioBuf, ioBufSize))
    {
        status = ERR_IPSEC;
        goto exit;
    }

    pSaBuf = ioBuf->pBuf;

    /* we increment by bytes instead of SADB because kernel and userspace SADB have different sizes */
    for (i=0; i < IPSEC_SADB_MAX; i++, pSaBuf += sadbSize)
    {
        if (OK > print_sadb((SADB)pSaBuf, i))
            break;
    }

exit:
    if (NULL != ioBuf)
        free(ioBuf);

    return status;
}
#endif /* !defined(LOADCONFIG_DUMP_TO_STDOUT) */


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
    sbyte4 status;
    ExtIpSecConf_t ioBuf;

    status = IPSEC_confPrepare1(pxConf, &ioBuf);
    if (status != OK)
        return status;

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

        IPSEC_keyPrepare(pxKeyTmp, &ioBuf);

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
    MOC_UNUSED(argSize);
    sbyte4 status = 0;

    if (0 > ipsecFid)
    {
        ipsecFid = open("/dev/moc_ipsec", O_RDWR);
    }

    if (0 > ipsecFid)
    {
        perror("Error opening moc_ipsec");
        status = -1;
        goto exit;
    }

    if (0 > (status = ioctl(ipsecFid, command, arg)))
    {
        perror("Error sending ioctl to moc_ipsec");
    }

    close(ipsecFid);
    ipsecFid = -1;

exit:
    return status;
}


#endif /* !defined(__ENABLE_DIGICERT_MISSIU__) */

#endif /* __RTOS_LINUX__ or __RTOS_ANDROID__ */

