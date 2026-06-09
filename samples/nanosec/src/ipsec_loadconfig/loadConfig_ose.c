/*
 * loadConfig_ose.c
 *
 * OSE platform IPsec configuration loader
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

#ifdef __RTOS_OSE__

#include <ose.h>
#include <ose.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "ose_spi/dda_core.h"
#include "ose_spi/pm.sig"
#include "ose_spi/mm.sig"
#include "ramlog.h"
#include "string.h"
#include "mm.h"

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

#include "../../examples/ipsec/ose/ose_ipsec.h"

#ifdef __ENABLE_DIGICERT_IPV6__
#error "Must not define __ENABLE_DIGICERT_IPV6__"
#endif


/*------------------------------------------------------------------*/

static sbyte4 IPSEC_sendSig(union SIGNAL *sig, sbyte4 *ret);


/*------------------------------------------------------------------*/

extern sbyte4
dumpSpd(ubyte4 address)
{
    sbyte4       status = 0;
    union SIGNAL *sig;
    sbyte4 st;

    sig = alloc(sizeof(ExtIpSecInt_t), IPSEC_SPD_DUMP_REQUEST);
    if (NIL == sig)
    {
        ERROR_PRINT(("Error in alloc()"));
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    sig->integer.value = (sbyte4)address;

    if (0 > (st = IPSEC_sendSig(sig, &status)))
        status = st;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
dumpSa(ubyte4 address)
{
    sbyte4       status = 0;
    union SIGNAL *sig;
    sbyte4 st;

    sig = alloc(sizeof(ExtIpSecInt_t), IPSEC_SADB_DUMP_REQUEST);
    if (NIL == sig)
    {
        ERROR_PRINT(("Error in alloc()"));
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    sig->integer.value = (sbyte4)address;

    if (0 > (st = IPSEC_sendSig(sig, &status)))
        status = st;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confFlush(void)
{
    sbyte4       status = 0;
    union SIGNAL *sig;
    sbyte4 st;

    sig = alloc(sizeof(ExtIpSecInt_t), IPSEC_CONF_FLUSH_REQUEST);
    if (NIL == sig)
    {
        ERROR_PRINT(("Error in alloc()"));
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (0 > (st = IPSEC_sendSig(sig, &status)))
        status = st;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyFlush(void)
{
    sbyte4       status = 0;
    union SIGNAL *sig;
    sbyte4 st;

    sig = alloc(sizeof(ExtIpSecInt_t), IPSEC_KEY_FLUSH_REQUEST);
    if (NIL == sig)
    {
        ERROR_PRINT(("Error in alloc()"));
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (0 > (st = IPSEC_sendSig(sig, &status)))
        status = st;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confAdd1(IPSECCONF pxConf)
{
    sbyte4       status = 0;
    union SIGNAL *sig;
    sbyte4 st;

    sig = alloc(sizeof(ExtIpSecConf_t), IPSEC_CONF_ADD_REQUEST);
    if (NIL == sig)
    {
        ERROR_PRINT(("Error in alloc()"));
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    memcpy((void *) &sig->conf.conf, (void *)pxConf, sizeof(struct ipsecConf));
    memcpy((void *) sig->conf.sa, (void *) pxConf->pxSa, sizeof(sig->conf.sa));

    if (0 > (st = IPSEC_sendSig(sig, &status)))
        status = st;
    else
    {
        pxConf->index = sig->conf.conf.index;
        free_buf(&sig);
    }

exit:
    return status;
} /* IPSEC_confAdd1 */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_keyAdd(IPSECKEY pxKey, sbyte4 num)
{
    sbyte4 status = 0;

    sbyte4 i;
    for (i = 0; i < num; i++)
    {
        IPSECKEY pxKeyTmp = pxKey + i;

        union SIGNAL *sig;
        sbyte4 st;

        sig = alloc(sizeof(ExtIpSecKey_t), IPSEC_KEY_ADD_REQUEST);
        if (NIL == sig)
        {
            ERROR_PRINT(("Error in alloc()"));
            status = ERR_MEM_ALLOC_FAIL;
            if (i) pxKeyTmp->status = status;
            break;
        }

        memcpy((void *) &sig->key.key, (void *)pxKeyTmp, sizeof(struct ipsecKey));

        if (pxKeyTmp->pAuthKey)
            memcpy((void *) sig->key.authKey, pxKeyTmp->pAuthKey,
                   pxKeyTmp->wAuthKeyLen);

        if (pxKeyTmp->pEncrKey)
            memcpy((void *) sig->key.encrKey, pxKeyTmp->pEncrKey,
                   pxKeyTmp->wEncrKeyLen);

        if (0 > (st = IPSEC_sendSig(sig, &status))
        {
            status = st;
            if (i) pxKeyTmp->status = status;
            break;
        }

        if (!status) pxKeyTmp->status = sig->key.key.status;
        else if (0 > status) pxKeyTmp->status = status;
        free_buf(&sig);

        if (1 > status) break;
    }

    if (i || (0 <= status)) /* !!! */
    status = i;

exit:
    return status;
} /* IPSEC_keyAdd */


/*------------------------------------------------------------------*/

static PROCESS mss_ipsec_pid = (PROCESS)0;

static sbyte4
IPSEC_sendSig(union SIGNAL *sig, sbyte4 *ret)
{
    sbyte4 status = 0;

    const SIGSELECT sigsel_reply[] =
    {
        1,
        sig->sig_no + MOC_IPSEC_CODE_MAX
    };

    if ((PROCESS)0 == mss_ipsec_pid)
    {
        if (0 == hunt("moc_ipsec", 0, &mss_ipsec_pid, NULL))
        {
            ERROR_PRINT(("Error in hunting moc_ipsec"));
            free_buf(&sig);
            status = -1;
            goto exit;
        }
    }

    send(&sig, mss_ipsec_pid);
    sig = receive_from(5000, sigsel_reply, mss_ipsec_pid);

    if (NIL == sig)
    {
        ERROR_PRINT(("Error in signaling moc_ipsec"));
        /*mss_ipsec_pid = (PROCESS)0;*/
        status = -1;
        goto exit;
    }

    *ret = sig->integer.value;
    free_buf(&sig);

exit:
    return status;
}


#endif /* __RTOS_OSE__ */

