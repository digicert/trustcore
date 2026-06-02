/*
 * loadConfig_missiu.c
 *
 * MISSIU IPsec configuration loader
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

#ifdef __ENABLE_DIGICERT_MISSIU__

#include <stdio.h>
#include <stdlib.h>

#include "missiu.h"

#ifdef LOADCONFIG_DUMP_TO_STDOUT
#include <string.h>
#include <time.h>
#include "merrors.h"
#ifdef __ENABLE_DIGICERT_IPV6__
#include "mstdlib.h"
#endif
#ifdef __ENABLE_IPSEC_ESN__
#include "int64.h"
#endif
#include "ipsec.h"
#include "ipsec_defs.h"
#include "ipsecconf.h"
#include "ipseckey.h"
#include "sadb.h"
#include "spd.h"
#include "ipsec_utils.h"
#include "ipsec_protos.h"
#include "../ipsec/linux/gpl/nf_ipsec.h"
#include "utils.inc"
#endif

static char *iface = NULL;

extern void
IPSEC_setInterface(char *arg)
{
    iface = arg;
}

#ifdef LOADCONFIG_DUMP_TO_STDOUT
extern sbyte4
dumpSpd(ubyte4 address)
{
    struct missiu_tlv *cmdbuf = NULL;
    struct missiu_shmem *shmem = NULL;
    MSTATUS status = OK;
    ExtIpSecDump_t *ioBuf = NULL;
    SPD pSpd;
    ubyte4 i;
    sbyte4 index = 0;
    sbyte4 mirrored = 0;

    /* create a TLV for the ioctl. */
    status = MISSIU_prepareTLV(IOC_DUMP_SPD, sizeof(struct missiu_shmem),
                               &cmdbuf);
    if (0 != status)
        goto done;

    /* create a shared mem segment to carry the argument */
    shmem = (struct missiu_shmem *)&cmdbuf->value[0];
    shmem->size = sizeof(ExtIpSecDump_t) + IPSEC_SPD_MAX * sizeof(struct spd);
    status = MISSIU_createSharedMem(shmem, (void **)&ioBuf);
    if (0 != status)
        goto done;

    /* prepare query */
    ioBuf->ip = address;
    ioBuf->bufLen = IPSEC_SPD_MAX * sizeof(struct spd);
    memset(ioBuf->pBuf, 0x00, ioBuf->bufLen);

    status = MISSIU_sendIoCtl(iface, cmdbuf);
    if (OK != status)
        goto done;

    /* process result */
    pSpd = (SPD)ioBuf->pBuf;

    for (i=0; i < IPSEC_SPD_MAX; i++, pSpd++)
    {
        if (OK > print_spd( pSpd, &index, &mirrored ))
            break;
    }

done:
    if (NULL != shmem)
        MISSIU_destroySharedMem(shmem, (void **)&ioBuf);

    if (NULL != cmdbuf)
        free(cmdbuf);

    return status;
}

extern sbyte4
dumpSa(ubyte4 address)
{
    sbyte4 status;
    ubyte4 sadbSize = 0;
    struct missiu_tlv *cmdbuf = NULL;
    ExtIpSecDump_t *ioBuf = NULL;
    struct missiu_shmem *shmem = NULL;
    ubyte4 i;
    ubyte *pSaBuf;

#ifdef OLD_MISSIU
    /* get the size of the SADB */
    status = MISSIU_ioctlSimpleGet(iface, IOC_GET_SADB_SIZE, &sadbSize);
    if (OK > status || 0 == sadbSize)
    {
        status = ERR_IPSEC;
        goto done;
    }
#else
    sadbSize = sizeof(struct sadb);
#endif

    /* create a TLV for the ioctl. */
    status = MISSIU_prepareTLV(IOC_DUMP_SA, sizeof(struct missiu_shmem),
                               &cmdbuf);
    if (0 != status)
        goto done;

    /* create a shared mem segment to carry the argument */
    shmem = (struct missiu_shmem *)&cmdbuf->value[0];
    shmem->size = sizeof(ExtIpSecDump_t) + IPSEC_SADB_MAX * sadbSize;
    status = MISSIU_createSharedMem(shmem, (void **)&ioBuf);
    if (0 != status)
        goto done;

    /* prepare query */
    memset(ioBuf, 0x0, shmem->size);
    ioBuf->ip = address;
    ioBuf->bufLen = IPSEC_SADB_MAX * sadbSize;
    memset(ioBuf->pBuf, 0x00, ioBuf->bufLen);

    status = MISSIU_sendIoCtl(iface, cmdbuf);
    if (OK != status)
        goto done;

#ifdef OLD_MISSIU
    /* we increment by bytes instead of SADB because kernel and userspace SADB
     * have different sizes
     */
#endif
    pSaBuf = ioBuf->pBuf;
    for (i=0; i < IPSEC_SADB_MAX; i++, pSaBuf += sadbSize)
    {
        if (OK > print_sadb((SADB)pSaBuf, i))
            break;
    }

done:
    if (NULL != shmem)
        MISSIU_destroySharedMem(shmem, (void **)&ioBuf);

    if (NULL != cmdbuf)
        free(cmdbuf);

    return status;
}

#else

extern sbyte4
dumpSpd(ubyte4 address)
{
    return MISSIU_ioctlSimple(iface, IOC_DUMP_SPD, address);
}

extern sbyte4
dumpSa(ubyte4 address)
{
    return MISSIU_ioctlSimple(iface, IOC_DUMP_SA, address);
}
#endif /* LOADCONFIG_DUMP_TO_STDOUT */

extern sbyte4
IPSEC_confFlush(void)
{
    return MISSIU_ioctlSimple(iface, IOC_FLUSH_SPD, 0);
}

extern sbyte4
IPSEC_keyFlush(void)
{
    return MISSIU_ioctlSimple(iface, IOC_FLUSH_SA, 0);
}

extern sbyte4
IPSEC_confPrepare1(IPSECCONF pxConf, ExtIpSecConf_t *ioBuf);

extern sbyte4
IPSEC_confAdd1(IPSECCONF pxConf)
{
    sbyte4 status;
    struct missiu_tlv *cmdbuf = NULL;
    ExtIpSecConf_t *ioBuf = NULL;
    struct missiu_shmem *shmem = NULL;

    /* create a TLV for the ioctl. */
    status = MISSIU_prepareTLV(IOC_ADD_CONF, sizeof(struct missiu_shmem),
                                 &cmdbuf);
    if (0 != status)
        goto done;

    /* create a shared mem segment to carry the config argument */
    shmem = (struct missiu_shmem *)&cmdbuf->value[0];
    shmem->size = sizeof(ExtIpSecConf_t);
    status = MISSIU_createSharedMem(shmem, (void **)&ioBuf);
    if (0 != status)
        goto done;

    status = IPSEC_confPrepare1(pxConf, ioBuf);
    if (0 != status)
        goto done;

    status = MISSIU_sendIoCtl(iface, cmdbuf);
    pxConf->index = ioBuf->conf.index;

done:
    MISSIU_destroySharedMem(shmem, (void **)&ioBuf);

    if (NULL != cmdbuf)
        free(cmdbuf);

    return status;
}

extern sbyte4 IPSEC_keyPrepare(IPSECKEY pxKey, ExtIpSecKey_t *ioBuf);

extern sbyte4
IPSEC_keyAdd(IPSECKEY pxKey, sbyte4 num)
{
    sbyte4 status = 0;
    sbyte4 i;
    ExtIpSecKey_t *ioBuf = NULL;
    struct missiu_tlv *cmdbuf = NULL;
    struct missiu_shmem *shmem = NULL;

    /* create a TLV for the ioctl. */
    status = MISSIU_prepareTLV(IOC_ADD_KEY, sizeof(struct missiu_shmem),
                                 &cmdbuf);
    if (0 != status)
        goto done;

    /* create a shared mem segment to carry the config argument */
    shmem = (struct missiu_shmem *)&cmdbuf->value[0];
    shmem->size = sizeof(ExtIpSecKey_t);
    status = MISSIU_createSharedMem(shmem, (void **)&ioBuf);
    if (0 != status)
        goto done;

    for (i = 0; i < num; i++)
    {
        IPSECKEY pxKeyTmp = pxKey + i;

        IPSEC_keyPrepare(pxKeyTmp, ioBuf);

        status = MISSIU_sendIoCtl(iface, cmdbuf);

        if (1 > status)
        {
            if (0 > status)
                pxKeyTmp->status = status;
            else
                pxKeyTmp->status = ioBuf->key.status;
            break;
        }
    }

    if (i || (0 <= status))
        status = i;

done:
    MISSIU_destroySharedMem(shmem, (void **)&ioBuf);

    if (NULL != cmdbuf)
        free(cmdbuf);

    return status;
}

#endif /* __ENABLE_DIGICERT_MISSIU__ */
