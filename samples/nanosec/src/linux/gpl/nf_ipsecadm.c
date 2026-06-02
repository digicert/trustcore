/*
 * nf_ipsecadm.c
 *
 * Administrative interface for IPsec kernel module
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Linking this program statically or dynamically with other modules is
 * making a combined work based on this program.  Thus, the terms and
 * conditions of the GNU General Public License cover the whole combination.
 *
 * As a special exception, the copyright holders of this program give you
 * permission to link this program with independent modules that
 * communicate with this program solely through the IPSEC_ interface,
 * regardless of the license terms of these independent modules, and to
 * copy and distribute the resulting combined work under terms of your
 * choice, provided that every copy of the combined work is accompanied by
 * a complete copy of the source code of this program (the version of this
 * program used to produce the combined work), being distributed under the
 * terms of the GNU General Public License plus this exception.
 * An independent module is a module which is not derived from or based on
 * this program.
 *
 * Note that people who make modified versions of this program are not
 * obligated to grant this special exception for their modified versions;
 * it is their choice whether to do so.  The GNU General Public License
 * gives permission to release a modified version without this exception;
 * this exception also makes it possible to release a modified version
 * which carries forward this exception.
 */

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
#include <linux/sched/signal.h>
#endif
#else
/* missiu */
#include <stdio.h>
#define printk(...) \
    do { \
		printf(__VA_ARGS__); \
		fflush(stdout); \
	} while (0)

#include <errno.h>
#include <mqueue.h>
#include "missiu.h"
#endif

#include "moptions.h"

#include "mtypes.h"
#include "mocana.h"
#include "hw_accel.h"

#include "mdefs.h"
#include "merrors.h"
#include "mstdlib.h"
#include "mrtos.h"
#include "debug_console.h"
#ifdef __ENABLE_IPSEC_ESN__
#include "int64.h"
#endif
#include "crypto.h"
#ifdef __ENABLE_DIGICERT_PFKEY__
#include "pfkey.h"
#endif
#include "ipsec.h"
#include "ipsecconf.h"
#include "ipseckey.h"
#include "ipsec_defs.h"
#include "ipsec_crypto.h"
#include "ipsec_utils.h"
#include "sadb.h"
#include "spd.h"
#include "ike.h"
#include "ike_event.h"
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
#include "if_mapping.h"
#endif

#include "nf_ipsec.h"

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
#define DB_PRINT printk
#define ERROR_PRINT(expr)
#endif

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)

IPSEC_keyReady_funcptr gM_IPSEC_keyReady_ptr = NULL;
IPSEC_getSpd_funcptr gM_IPSEC_getSpd_ptr = NULL;
IPSEC_confDelete_funcptr gM_IPSEC_confDelete_ptr = NULL;
DIGI_deltaMS_funcptr gM_DIGI_deltaMS_ptr = NULL;

/*------------------------------------------------------------------*/

moctime_t *gM_gStartTime;
#else
extern moctime_t *gStartTime;
#endif

#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
extern intBoolean m_ipsecSadbForever;
#endif
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
extern ifmap_entry m_ifmap_kern;
#endif
#ifdef __KERNEL__
extern ModStats_t modStats;

/*------------------------------------------------------------------*/

static void
ips_dumpStats(int reset)
{
    printk("\n");
    printk("In bytes: %d, out bytes: %d\n",
       (int)modStats.input.bytes, (int)modStats.output.bytes);
    printk("Incount:  %d [%d decrypted, %d errs]\n",
           (int)modStats.input.all,
       (int)modStats.input.applied, (int)modStats.input.errors);
    printk("MaxSize = %d, Last err: %d\n",
           (int)modStats.input.maxSize, (int)modStats.input.lastErr);
    printk("Outcount: %d [%d encrypted, %d errs]\n",
           (int)modStats.output.all,
       (int)modStats.output.applied, (int)modStats.output.errors);
    printk("MaxSize = %d, Last err: %d\n",
           (int)modStats.output.maxSize, (int)modStats.output.lastErr);
    printk("# IP frags: %d, # fragments: %d\n",
           (int)modStats.output.nIpFrags,
           (int)modStats.output.numFragments);
    printk("IKE sent:%d\n", (int)modStats.output.ikeMsgs);
    printk("Trace:%d RunFlags=%x\n",
           (int)modStats.trace, (int)modStats.runFlags);
    if (reset)
    {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMSET_ptr((void *)&modStats.output,  0, sizeof(modStats.output));
        gM_DIGI_MEMSET_ptr((void *)&modStats.input, 0, sizeof(modStats.input));
#else
        DIGI_MEMSET((void *)&modStats.output,  0, sizeof(modStats.output));
        DIGI_MEMSET((void *)&modStats.input, 0, sizeof(modStats.input));
#endif
    }
}

#else
/* TODO: Implement dumpStats for missiu */
static void
ips_dumpStats(int reset)
{

}
#endif


/*------------------------------------------------------------------*/

static sbyte4
ipsadm_addKey(ExtIpSecKey_t *extKeyData)
{
    sbyte4   status;
    IPSECKEY keyData = &extKeyData->key;

    if (keyData->pAuthKey) keyData->pAuthKey = extKeyData->authKey;
    if (keyData->pEncrKey) keyData->pEncrKey = extKeyData->encrKey;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & keyData->flags)
    {
        if (keyData->dwDestAddr)
            keyData->dwDestAddr = (CAST_MOC_IPADDR) extKeyData->dstAddr;
        if (keyData->dwSrcAddr)
            keyData->dwSrcAddr = (CAST_MOC_IPADDR) extKeyData->srcAddr;
    }
#endif

    /*DUMP_LONGS((ubyte *)keyData, sizeof(*keyData), 80, "Key Add Info");*/

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (1 != (status = gM_IPSEC_keyAdd_ptr(keyData, 1)))
#else
    if (1 != (status = IPSEC_keyAdd(keyData, 1)))
#endif
    {
        ERROR_PRINT(("Error adding key (spi=%x), status=%d", keyData->dwSpi, status ? status : keyData->status));
        goto exit;
    }
    DBUG_PRINT(DEBUG_IPSEC, ("Key (spi=%x) added", keyData->dwSpi));

exit:
    return status;
}


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
static sbyte4
ipsadm_getKeyEx(ExtIpSecKeyEx_t *extKeyData)
{
    sbyte4   status;
    IPSECKEY_EX keyData = &extKeyData->key;

    keyData->poAuthKey = extKeyData->authKey;
    keyData->poEncrKey = extKeyData->encrKey;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & keyData->flags)
    {
        keyData->dwDestAddr = (CAST_MOC_IPADDR) extKeyData->dstAddr;
    }
#endif

    /*DUMP_LONGS((ubyte *)keyData, sizeof(*keyData), 80, "Key Get Info");*/

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (0 != (status = gM_IPSEC_keyGetEx_ptr(keyData)))
#else
    if (0 != (status = IPSEC_keyGetEx(keyData)))
#endif
    {
        ERROR_PRINT(("Error getting key (spi=%x)", keyData->dwSpi));
        goto exit;
    }
    DBUG_PRINT(DEBUG_IPSEC, ("Key (spi=%x) found", keyData->dwSpi));

exit:
    return status;
}
#endif
/*------------------------------------------------------------------*/

static sbyte4
ipsadm_getKey(ExtIpSecKey_t *extKeyData)
{
    sbyte4   status;
    IPSECKEY keyData = &extKeyData->key;

    keyData->pAuthKey = extKeyData->authKey;
    keyData->pEncrKey = extKeyData->encrKey;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SA_FLAG_IP6 & keyData->flags)
    {
        keyData->dwDestAddr = (CAST_MOC_IPADDR) extKeyData->dstAddr;
    }
#endif

    /*DUMP_LONGS((ubyte *)keyData, sizeof(*keyData), 80, "Key Get Info");*/

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (0 != (status = gM_IPSEC_keyGet_ptr(keyData)))
#else
    if (0 != (status = IPSEC_keyGet(keyData)))
#endif
    {
        ERROR_PRINT(("Error getting key (spi=%x)", keyData->dwSpi));
        goto exit;
    }
    DBUG_PRINT(DEBUG_IPSEC, ("Key (spi=%x) found", keyData->dwSpi));

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if !defined(LOADCONFIG_DUMP_TO_STDOUT)

#ifdef __ENABLE_DIGICERT_IPV6__
static void dumpIP6(MOC_IP_ADDRESS addr)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        pr_cont("%02x", ((ubyte *)addr->uin.addr6)[i]);
        if (i % 2 != 0 && i != 15)
            pr_cont(":");
    }
}
#endif

static void
ipsadm_dumpSA(ubyte4 address)
{
    int   j;
    ubyte *sp;
    SADB pxSa = NULL;

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    while (NULL != (pxSa = gM_IPSEC_enumSa_ptr(pxSa)))
#else
    while (NULL != (pxSa = IPSEC_enumSa(pxSa)))
#endif
    {
        if (0 != address)
        {
            IF_MOC_IPADDR6(pxSa->dwSaDestAddr, { continue; } )

            if ((address != RET_MOC_IPADDR4(pxSa->dwSaSrcAddr)) &&
                (address != RET_MOC_IPADDR4(pxSa->dwSaDestAddr)))
                continue;
        }
        printk("==== SPI:    %x\n", pxSa->dwSaSpi);
        printk("Flags: 0x%x, ", pxSa->saFlags);
        pr_cont("Proto: %d, ", (int) pxSa->oSaProto);
        pr_cont("ULP:   %d, ", (int) pxSa->oSaUlp);
        pr_cont("Mode:  %d\n", (int) pxSa->oSaMode);
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxSa->dwSaDestAddr.family == AF_INET6)
        {
            printk("Source.addr: ");
            dumpIP6(REF_MOC_IPADDR(pxSa->dwSaSrcAddr));
            pr_cont("\nDest.addr: ");
            dumpIP6(REF_MOC_IPADDR(pxSa->dwSaDestAddr));
            pr_cont("\n");
        }
        else
#endif
        {
            ubyte4 src = (ubyte4)RET_MOC_IPADDR4(pxSa->dwSaSrcAddr);
            ubyte4 dst = (ubyte4)RET_MOC_IPADDR4(pxSa->dwSaDestAddr);
            printk("Source.addr: %u.%u.%u.%u\n",
                   (src >> 24) & 0xff, (src >> 16) & 0xff,
                   (src >>  8) & 0xff,  src        & 0xff);
            printk("Dest.addr:   %u.%u.%u.%u\n",
                   (dst >> 24) & 0xff, (dst >> 16) & 0xff,
                   (dst >>  8) & 0xff,  dst        & 0xff);
        }
        if (pxSa->wSaSrcPort || pxSa->wSaDestPort)
        {
            printk("Source.port: %d, ", (int) pxSa->wSaSrcPort);
            pr_cont("Dest.port:   %d\n", (int) pxSa->wSaDestPort);
        }
        if (NULL != pxSa->pHmacSuite)
        {
            printk("Auth.algo:   %d\n", (int) pxSa->pHmacSuite->oAuthAlgo);
            printk("Auth.key: ");
            for (j = pxSa->pHmacSuite->wKeyLen - 1, sp = pxSa->poAuthKey; j >= 0;
                 j--, sp++)
            {
                pr_cont("%02X.", *sp);
            }
            pr_cont("\n");
        }
        if (NULL != pxSa->pCipherSuite)
        {
            printk("Encr.algo:   %d\n", (int) pxSa->pCipherSuite->oEncrAlgo);
            printk("Encr.key: ");
            for (j = pxSa->wEncrKeyLen - 1, sp = pxSa->poEncrKey; j >= 0;
                 j--, sp++)
            {
                pr_cont("%02X.", *sp);
            }
            pr_cont("\n");
        }

        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            ubyte4 timenow = gM_DIGI_deltaMS_ptr(gM_gStartTime, NULL);
#else
            ubyte4 timenow = RTOS_deltaMS(gStartTime, NULL);
#endif
            printk("Usage: %u", (unsigned)((timenow - pxSa->dwSaEstablished) / 1000));
            if (pxSa->dwSaExpSecs)
                pr_cont("/%u", (unsigned) pxSa->dwSaExpSecs);
            pr_cont(" secs, ");
        }
        if (pxSa->dwSaCurKBytes || pxSa->wSaCurBytes)
        {
            pr_cont("%u.%d", (unsigned) pxSa->dwSaCurKBytes,
                   (pxSa->wSaCurBytes * 1000) / 1024);
            if (pxSa->dwSaExpKBytes)
                pr_cont("/%u", (unsigned) pxSa->dwSaExpKBytes);
            pr_cont(" kbytes, ");
        }

        pr_cont("%u", (unsigned) pxSa->dwSaCurPackets);
        if (pxSa->dwSaTotPackets &&
            (pxSa->dwSaCurPackets != pxSa->dwSaTotPackets))
            pr_cont("/%u", (unsigned) pxSa->dwSaTotPackets);
        pr_cont(" pkts\n");

#if defined(IPSEC_REPLAY_SIZE) && defined(__ENABLE_DIGICERT_IKE_SERVER__)
        if ((NULL != pxSa->pxSp) &&
            (IPSEC_SA_FLAG_INBOUND & pxSa->saFlags))
        {
#ifndef __ENABLE_IPSEC_ESN__
            ubyte4 dwSeqNbr = ATOMIC_GET(pxSa->u.i.seqB);
#else
            ubyte8 seq = ATOMIC_GET(pxSa->u.i.seqB);
            ubyte4 dwSeqNbrHi = HI_U8(seq);
            ubyte4 dwSeqNbr = LOW_U8(seq);

            if ((IPSEC_SA_FLAG_ESN & pxSa->saFlags) && (0 != dwSeqNbrHi))
                printk("Seq: [%u]%u(+%d)\n",
                       (unsigned)dwSeqNbrHi, (unsigned)dwSeqNbr, IPSEC_REPLAY_SIZE);
            else
#endif
            printk("Seq: %u(+%d)\n", (unsigned)dwSeqNbr, IPSEC_REPLAY_SIZE);
        }
        else
#endif
        {
#ifndef __ENABLE_IPSEC_ESN__
            ubyte4 dwSeqNbr = ATOMIC_GET(pxSa->u.o.seq);
#else
            ubyte8 seq = ATOMIC_GET(pxSa->u.o.seq);
            ubyte4 dwSeqNbrHi = HI_U8(seq);
            ubyte4 dwSeqNbr = LOW_U8(seq);

            if (!(IPSEC_SA_FLAG_INBOUND & pxSa->saFlags) &&
                (IPSEC_SA_FLAG_ESN & pxSa->saFlags) && (0 != dwSeqNbrHi))
                printk("Seq: [%u]%u\n", (unsigned)dwSeqNbrHi, (unsigned)dwSeqNbr);
            else
#endif
            if (dwSeqNbr && (dwSeqNbr != pxSa->dwSaCurPackets))
                printk("Seq: %u\n", (unsigned)dwSeqNbr);
        }
        printk("\n");
    }
}

#else

static void
ipsadm_dumpSA(ExtIpSecDump_t *extDumpData)
{
    sbyte4 i, num;
    SADB   pSa = NULL;
    SADB   pSaTmp;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    ubyte4 timenow = gM_DIGI_deltaMS_ptr(gM_gStartTime, NULL);
#else
    ubyte4 timenow = RTOS_deltaMS(gStartTime, NULL);
#endif

    if (NULL == extDumpData)
        return;

    pSaTmp = (SADB)extDumpData->pBuf;
    num = extDumpData->bufLen / sizeof(struct sadb);

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    for (i=0; (i < num) && (pSa = gM_IPSEC_enumSa_ptr(pSa)); i++, pSaTmp++)
#else
    for (i=0; (i < num) && (pSa = IPSEC_enumSa(pSa)); i++, pSaTmp++)
#endif
    {
        memmove(pSaTmp, pSa, sizeof(struct sadb));

        if (pSa->pHmacSuite)
            pSaTmp->pHmacSuite = (SADB_hmacSuiteInfo *)((ubyte4) pSa->pHmacSuite->oAuthAlgo);
        if (pSa->pCipherSuite)
            pSaTmp->pCipherSuite = (SADB_cipherSuiteInfo *)((ubyte4) pSa->pCipherSuite->oEncrAlgo);

        pSaTmp->dwSaEstablished = timenow - pSaTmp->dwSaEstablished;
        if (pSaTmp->dwSaLastUsed) pSaTmp->dwSaLastUsed = timenow - pSaTmp->dwSaLastUsed;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (pSaTmp->dwSaFirstUsed) pSaTmp->dwSaFirstUsed = timenow - pSaTmp->dwSaFirstUsed;
        if (pSaTmp->pxSp) pSaTmp->pxSp = (SPD) pSaTmp->pxSp->index;
#endif
#if 1 /* !defined(__ENABLE_DIGICERT_MISSIU__) */
        /* atomic_t only exists in kernel (vs. userland) - see "sadb.h" */
        pSaTmp->u.d.seq = ATOMIC_GET(pSaTmp->u.o.seq);
#endif
    }
    if (i < num) pSaTmp->saFlags = 0;

    extDumpData->bufLen = i;
    return;
}

static void
ipsadm_dumpSA_compat(ExtIpSecDump_t *extDumpData)
{
    sbyte4 i, num;
    SADB   pSa = NULL;
    SADBCOMPAT   pSaTmp;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    ubyte4 timenow = gM_DIGI_deltaMS_ptr(gM_gStartTime, NULL);
#else
    ubyte4 timenow = RTOS_deltaMS(gStartTime, NULL);
#endif

    if (NULL == extDumpData)
        return;

    pSaTmp = (SADBCOMPAT)extDumpData->pBuf;
    num = extDumpData->bufLen / sizeof(struct sadbCompat);

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    for (i=0; (i < num) && (pSa = gM_IPSEC_enumSa_ptr(pSa)); i++, pSaTmp++)
#else
    for (i=0; (i < num) && (pSa = IPSEC_enumSa(pSa)); i++, pSaTmp++)
#endif
    {
        pSaTmp->saFlags = pSa->saFlags;
        pSaTmp->oSaProto = pSa->oSaProto;
        pSaTmp->dwSaSpi = pSa->dwSaSpi;
        pSaTmp->dwSaDestAddr = pSa->dwSaDestAddr;
        pSaTmp->dwSaSrcAddr = pSa->dwSaSrcAddr;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
        pSaTmp->cookie = pSa->cookie;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        pSaTmp->wSaUdpEncPort = pSa->wSaUdpEncPort;
#endif
        pSaTmp->wSaDestPort = pSa->wSaDestPort;
        pSaTmp->wSaSrcPort = pSa->wSaSrcPort;
        pSaTmp->oSaUlp = pSa->oSaUlp;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        pSaTmp->oSaMode = pSa->oSaMode;
        pSaTmp->dwSaDestIP = pSa->dwSaDestIP;
        pSaTmp->dwSaDestIPEnd = pSa->dwSaDestIPEnd;
        pSaTmp->dwSaSrcIP = pSa->dwSaSrcIP;
        pSaTmp->dwSaSrcIPEnd = pSa->dwSaSrcIPEnd;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSaTmp->dwSaSrcIPList, pSa->dwSaSrcIPList, MAX_IP_IN_FQDN *
                                sizeof(MOC_IP_ADDRESS_S));
        gM_DIGI_MEMCPY_ptr(pSaTmp->dwSaDestIPList, pSa->dwSaDestIPList, MAX_IP_IN_FQDN *
                                sizeof(MOC_IP_ADDRESS_S));
#else
        DIGI_MEMCPY(pSaTmp->dwSaSrcIPList, pSa->dwSaSrcIPList, MAX_IP_IN_FQDN *
                                sizeof(MOC_IP_ADDRESS_S));
        DIGI_MEMCPY(pSaTmp->dwSaDestIPList, pSa->dwSaDestIPList, MAX_IP_IN_FQDN *
                                sizeof(MOC_IP_ADDRESS_S));
#endif
        pSaTmp->dwSaDestIPCount = pSa->dwSaDestIPCount;
        pSaTmp->dwSaSrcIPCount = pSa->dwSaSrcIPCount;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSaTmp->fqdn, pSa->fqdn, MOC_MAX_FQDN_LEN);
#else
        DIGI_MEMCPY(pSaTmp->fqdn, pSa->fqdn, MOC_MAX_FQDN_LEN);
#endif
        pSaTmp->inbound = pSa->inbound;
        pSaTmp->fqdnUniqueKey = pSa->fqdnUniqueKey;
#endif
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSaTmp->poAuthKey, pSa->poAuthKey, IPSEC_AUTHKEY_MAX);
        pSaTmp->wEncrKeyLen = pSa->wEncrKeyLen;
        gM_DIGI_MEMCPY_ptr(pSaTmp->poEncrKey, pSa->poEncrKey, IPSEC_ENCRKEY_MAX);
#else
        DIGI_MEMCPY(pSaTmp->poAuthKey, pSa->poAuthKey, IPSEC_AUTHKEY_MAX);
        pSaTmp->wEncrKeyLen = pSa->wEncrKeyLen;
        DIGI_MEMCPY(pSaTmp->poEncrKey, pSa->poEncrKey, IPSEC_ENCRKEY_MAX);
#endif
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
        pSaTmp->users = pSa->users;
#endif
#ifdef __IPSEC_SINGLE_PASS_SUPPORT__
        pSaTmp->dwSinglePassCookie = pSa->dwSinglePassCookie;
#endif
        pSaTmp->dwSaEstablished = pSa->dwSaEstablished;
        pSaTmp->dwSaExpSecs = pSa->dwSaExpSecs;
        pSaTmp->wSaCurBytes = pSa->wSaCurBytes;
        pSaTmp->dwSaCurKBytes = pSa->dwSaCurKBytes;
        pSaTmp->dwSaExpKBytes = pSa->dwSaExpKBytes;
        pSaTmp->dwSaTotPackets = pSa->dwSaTotPackets;
        pSaTmp->dwSaCurPackets = pSa->dwSaCurPackets;
        pSaTmp->dwSaLastUsed = pSa->dwSaLastUsed;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        pSaTmp->dwSaFirstUsed = pSa->dwSaFirstUsed;
        pSaTmp->dwSaLastRekey = pSa->dwSaLastRekey;
        pSaTmp->dwIdM = pSa->dwIdM;
        pSaTmp->dwSpdId = pSa->dwSpdId;
        pSaTmp->iNest = pSa->iNest;
        pSaTmp->dwIkeSaId = pSa->dwIkeSaId;
        pSaTmp->ikeSaLoc = pSa->ikeSaLoc;
#endif
        pSaTmp->dwId = pSa->dwId;
#ifdef IPSEC_REPLAY_SIZE
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSaTmp->u.i.poReplayWindow, pSa->u.i.poReplayWindow, (IPSEC_REPLAY_SIZE / 8));
#else
        DIGI_MEMCPY(pSaTmp->u.i.poReplayWindow, pSa->u.i.poReplayWindow, (IPSEC_REPLAY_SIZE / 8));
#endif
#endif

        if (pSa->pHmacSuite)
            pSaTmp->pHmacSuite = ((ubyte4) pSa->pHmacSuite->oAuthAlgo);
        if (pSa->pCipherSuite)
            pSaTmp->pCipherSuite = ((ubyte4) pSa->pCipherSuite->oEncrAlgo);

        pSaTmp->dwSaEstablished = timenow - pSaTmp->dwSaEstablished;
        if (pSaTmp->dwSaLastUsed) pSaTmp->dwSaLastUsed = timenow - pSaTmp->dwSaLastUsed;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        if (pSaTmp->dwSaFirstUsed) pSaTmp->dwSaFirstUsed = timenow - pSaTmp->dwSaFirstUsed;
        if (pSa->pxSp) pSaTmp->pxSp = (ubyte4) pSa->pxSp->index;
#endif
#if 1 /* !defined(__ENABLE_DIGICERT_MISSIU__) */
        /* atomic_t only exists in kernel (vs. userland) - see "sadb.h" */
        pSaTmp->u.d.seq = ATOMIC_GET(pSa->u.o.seq);
#endif
    }
    if (i < num) pSaTmp->saFlags = 0;

    extDumpData->bufLen = i * sizeof(struct sadbCompat);
    return;
}


#endif /* !defined(LOADCONFIG_DUMP_TO_STDOUT) */


/*------------------------------------------------------------------*/

static sbyte4
ipsadm_addKeyEx(ExtIpSecKeyEx_t *extKeyData)
{
    sbyte4      status;
    IPSECKEY_EX keyData = &extKeyData->key;

    if (keyData->poAuthKey) keyData->poAuthKey = extKeyData->authKey;
    if (keyData->poEncrKey) keyData->poEncrKey = extKeyData->encrKey;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (keyData->dwDestAddr) keyData->dwDestAddr = &extKeyData->dstAddr;
    if (keyData->dwSrcAddr)  keyData->dwSrcAddr  = &extKeyData->srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (keyData->dwDestIP)    keyData->dwDestIP    = &extKeyData->dstIP;
    if (keyData->dwDestIPEnd) keyData->dwDestIPEnd = &extKeyData->dstIPend;
    if (keyData->dwSrcIP)     keyData->dwSrcIP     = &extKeyData->srcIP;
    if (keyData->dwSrcIPEnd)  keyData->dwSrcIPEnd  = &extKeyData->srcIPend;
#endif
#endif

    /*DUMP_LONGS((ubyte *)keyData, sizeof(*keyData), 80, "KeyEx Add Info");*/

#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    status = gM_IPSEC_groupKeyAdd_ptr(keyData);
#else
    status = IPSEC_groupKeyAdd(keyData);
#endif
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    status = gM_IPSEC_keyAddEx_ptr(keyData);
#else
    status = IPSEC_keyAddEx(keyData);
#endif
#endif
    if (0 > status)
    {
        ERROR_PRINT(("Error adding keyEx (spi=%x): status=%d", keyData->dwSpi, status));
        goto exit;
    }
    DBUG_PRINT(DEBUG_IPSEC, ("Key (spi=%x) added", keyData->dwSpi));
    /*ipsadm_dumpSA(0);*/

exit:
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__
static sbyte4
ipsadm_readyKey(ExtIpSecKeyEx_t *extKeyData)
{
    sbyte4      status;
    IPSECKEY_EX keyData = &extKeyData->key;

    if (keyData->dwDestAddr) keyData->dwDestAddr = &extKeyData->dstAddr;
    if (keyData->dwSrcAddr)  keyData->dwSrcAddr  = &extKeyData->srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (keyData->dwDestIP)    keyData->dwDestIP    = &extKeyData->dstIP;
    if (keyData->dwDestIPEnd) keyData->dwDestIPEnd = &extKeyData->dstIPend;
    if (keyData->dwSrcIP)     keyData->dwSrcIP     = &extKeyData->srcIP;
    if (keyData->dwSrcIPEnd)  keyData->dwSrcIPEnd  = &extKeyData->srcIPend;
#endif
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    status = gM_IPSEC_keyReady_ptr(keyData);
#else
    status = IPSEC_keyReady(keyData);
#endif

    return status;
}
#endif


/*------------------------------------------------------------------*/

static sbyte4
ipsadm_addConf(ExtIpSecConf_t *extConfData)
{
    sbyte4    status;
    IPSECCONF pxConf = &extConfData->conf;

    pxConf->pxSa = extConfData->sa;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (IPSEC_SP_FLAG_IP6 & pxConf->flags)
    {
        if (pxConf->dwSrcIP)
            pxConf->dwSrcIP     = (CAST_MOC_IPADDR) extConfData->srcIP;
        if (pxConf->dwSrcIPEnd)
            pxConf->dwSrcIPEnd  = (CAST_MOC_IPADDR) extConfData->srcIPend;
        if (pxConf->dwDestIP)
            pxConf->dwDestIP    = (CAST_MOC_IPADDR) extConfData->dstIP;
        if (pxConf->dwDestIPEnd)
            pxConf->dwDestIPEnd = (CAST_MOC_IPADDR) extConfData->dstIPend;
    }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_SP_FLAG_IP6_TUNNEL & pxConf->flags)
    {
        if (pxConf->dwTunlDestIP)
            pxConf->dwTunlDestIP = (CAST_MOC_IPADDR) extConfData->tunDstIP;
        if (pxConf->dwTunlSrcIP)
            pxConf->dwTunlSrcIP  = (CAST_MOC_IPADDR) extConfData->tunSrcIP;
    }
#endif
#endif /* __ENABLE_DIGICERT_IPV6__ */
#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    m_ipsecSadbForever = extConfData->rekeyForever;
#endif
    /*DUMP_LONGS((ubyte *)extConfData, sizeof(*extConfData), 80, "Conf data");*/

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (OK > (status = gM_IPSEC_confAdd1_ptr(pxConf)))
#else
    if (OK > (status = IPSEC_confAdd1(pxConf)))
#endif
    {
        ERROR_PRINT(("Error adding policy, status=%d", status));
        goto exit;
    }
    DBUG_PRINT(DEBUG_IPSEC, ("Policy added"));

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if !defined(LOADCONFIG_DUMP_TO_STDOUT)

static void
ipsadm_dumpSPD(ubyte4 address)
{
    int   i, j, numEntries;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    SPD   pSpd = gM_IPSEC_getSpd_ptr(&numEntries);
#else
    SPD   pSpd = IPSEC_getSpd(&numEntries);
#endif

    if ((0 > numEntries) || (NULL == pSpd))
        return;

    for (i = 0; i < numEntries; i++, pSpd++)
    {
        if (!(IPSEC_SP_FLAG_INUSE & pSpd->flags) ||
             (IPSEC_SP_FLAG_DELETED & pSpd->flags))
            continue;

        if (0 != address)
        {
            IF_MOC_IPADDR6(pSpd->dwSrcIP, { continue; } )

            if ((address != RET_MOC_IPADDR4(pSpd->dwSrcIP)) &&
                (address != RET_MOC_IPADDR4(pSpd->dwDestIP)))
                continue;
        }
        printk("==== INDEX:    %x [%s]\n", pSpd->index,
                 (0 == (i&1)) ? "IN" : "OUT");
        printk("Flags: %04x, Proto: %d, Action: %d\n",
                 pSpd->flags, pSpd->oProto, pSpd->oAction);
        printk("Source.addr: ");

#ifdef __ENABLE_DIGICERT_IPV6__
        if (pSpd->dwSrcIP.family == AF_INET6)
        {
            dumpIP6(REF_MOC_IPADDR(pSpd->dwSrcIP));
            pr_cont("->");
            dumpIP6(REF_MOC_IPADDR(pSpd->dwSrcIPEnd));
            pr_cont("\n");
        }
        else
#endif
        {
            pr_cont("%08x->%08x\n",
                   (int) RET_MOC_IPADDR4(pSpd->dwSrcIP),
                   (int) RET_MOC_IPADDR4(pSpd->dwSrcIPEnd));
        }

        printk("Dest.addr:   ");
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pSpd->dwDestIP.family == AF_INET6)
        {
            dumpIP6(REF_MOC_IPADDR(pSpd->dwDestIP));
            pr_cont("->");
            dumpIP6(REF_MOC_IPADDR(pSpd->dwDestIPEnd));
            pr_cont("\n");
        }
        else
#endif
        {
            pr_cont("%08x->%08x\n",
                   (int) RET_MOC_IPADDR4(pSpd->dwDestIP),
                   (int) RET_MOC_IPADDR4(pSpd->dwDestIPEnd));
        }

        printk("Source.port: %08x", pSpd->wSrcPort);
#ifdef __ENABLE_IPSEC_PORT_RANGE__
        pr_cont("->%08x", pSpd->wSrcPortEnd);
#endif
        pr_cont("\n");
        printk("Dest.port:   %08x", pSpd->wDestPort);
#ifdef __ENABLE_IPSEC_PORT_RANGE__
        pr_cont("->%08x", pSpd->wDestPortEnd);
#endif
        pr_cont("\n");
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (pSpd->oMode == IPSEC_MODE_TUNNEL)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (pSpd->dwSrcIP.family == AF_INET6)
            {
                printk("Dest.tunnel/Src.tunnel:   ");
                dumpIP6(REF_MOC_IPADDR(pSpd->dwTunlDestIP));
                pr_cont("->");
                dumpIP6(REF_MOC_IPADDR(pSpd->dwTunlSrcIP));
                pr_cont("\n");
            }
            else
#endif
            {
                printk("Dest.tunnel/Src.tunnel:   %08x->%08x\n",
                       (int) RET_MOC_IPADDR4(pSpd->dwTunlDestIP),
                       (int) RET_MOC_IPADDR4(pSpd->dwTunlSrcIP));
            }
        }
#endif
        for (j = 0; j < pSpd->oSaLen; j++)
        {
            printk("%d.SecuProto: %d\n",
                     j, pSpd->pxSa[j].oSecuProto);
            printk("%d.AuthAlgo:  %d\n",
                     j, pSpd->pxSa[j].oAuthAlgo);
            printk("%d.EncrAlgo:  %d\n",
                     j, pSpd->pxSa[j].oEncrAlgo);
            printk("%d.EncrLen:   %d\n",
                     j, pSpd->pxSa[j].oEncrKeyLen);
        }

        if (0 != pSpd->dwTotPackets)
        {
            printk("Usage: ");

            switch (pSpd->oAction)
            {
            case IPSEC_ACTION_APPLY :
            case IPSEC_ACTION_PERMIT :
                pr_cont("%lu", (unsigned long) pSpd->dwCurPackets);
                if (pSpd->dwTotPackets != pSpd->dwCurPackets)
                    pr_cont("/%lu", (unsigned long) pSpd->dwTotPackets);
                pr_cont(" pkts, %lu.%d kbytes",
                        (unsigned long) pSpd->dwCurKBytes,
                        (pSpd->wCurBytes * 1000) / 1024);
                break;
            default :
                pr_cont("%lu pkts", (unsigned long) pSpd->dwTotPackets);
                break;
            }

            pr_cont("\n");
        }
    }
}

#else

static void
ipsadm_dumpSPD(ExtIpSecDump_t *extDumpData)
{
    sbyte4  i, num;
    SPD     pSpd = NULL;
    SPD     pSpdTmp;

    if (NULL == extDumpData)
        return;

    pSpdTmp = (SPD)extDumpData->pBuf;
    num = extDumpData->bufLen / sizeof(struct spd);

    for (i=0; (i < num) && (pSpd = IPSEC_enumSp(pSpd)); i++, pSpdTmp++)
    {
        memmove(pSpdTmp, pSpd, sizeof(struct spd));
    }
    if (i < num) pSpdTmp->flags = 0;

    extDumpData->bufLen = i;
}

static void
ipsadm_dumpSPD_compat(ExtIpSecDump_t *extDumpData)
{
    sbyte4  i, num;
    SPD     pSpd = NULL;
    SPDCOMPAT     pSpdTmp;

    if (NULL == extDumpData)
        return;

    pSpdTmp = (SPDCOMPAT)extDumpData->pBuf;
    num = extDumpData->bufLen / sizeof(struct spdCompat);

    for (i=0; (i < num) && (pSpd = IPSEC_enumSp(pSpd)); i++, pSpdTmp++)
    {
        pSpdTmp->index = pSpd->index;
        pSpdTmp->flags = pSpd->flags;
        pSpdTmp->dwDestIP = pSpd->dwDestIP;
        pSpdTmp->dwDestIPEnd = pSpd->dwDestIPEnd;
        pSpdTmp->wDestPort = pSpd->wDestPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
        pSpdTmp->wDestPortEnd = pSpd->wDestPortEnd;
#endif
        pSpdTmp->wDestPortCount = pSpd->wDestPortCount;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSpdTmp->wDestPortList, pSpd->wDestPortList,
#else
        DIGI_MEMCPY(pSpdTmp->wDestPortList, pSpd->wDestPortList,
#endif
                                MAX_PORTS_PER_POLICY * sizeof(ubyte2));
        pSpdTmp->wDestPortType = pSpd->wDestPortType;
        pSpdTmp->dwSrcIP = pSpd->dwSrcIP;
        pSpdTmp->dwSrcIPEnd = pSpd->dwSrcIPEnd;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSpdTmp->wPortList, pSpd->wPortList,
#else
        DIGI_MEMCPY(pSpdTmp->wPortList, pSpd->wPortList,
#endif
                                MAX_PORTS_PER_POLICY * sizeof(ubyte2));
        pSpdTmp->wPortCount = pSpd->wPortCount;
        pSpdTmp->wSrcPort = pSpd->wSrcPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
        pSpdTmp->wSrcPortEnd = pSpd->wSrcPortEnd;
#endif
        pSpdTmp->oProto = pSpd->oProto;
        pSpdTmp->oAction = pSpd->oAction;
        pSpdTmp->oMode = pSpd->oMode;
        pSpdTmp->dwTunlDestIP = pSpd->dwTunlDestIP;
        pSpdTmp->dwTunlSrcIP = pSpd->dwTunlSrcIP;
        pSpdTmp->oSaLen = pSpd->oSaLen;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSpdTmp->pxSa, pSpd->pxSa,
#else
        DIGI_MEMCPY(pSpdTmp->pxSa, pSpd->pxSa,
#endif
                                IPSEC_NEST_MAX * sizeof(struct sainfo));
        pSpdTmp->dwCurPackets = pSpd->dwCurPackets;
        pSpdTmp->wCurBytes = pSpd->wCurBytes;
        pSpdTmp->dwCurKBytes = pSpd->dwCurKBytes;
        pSpdTmp->dwTotPackets = pSpd->dwTotPackets;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
        pSpdTmp->ifid = pSpd->ifid;
#endif
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
        pSpdTmp->cookie = pSpd->cookie;
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
        pSpdTmp->dwSaSecs = pSpd->dwSaSecs;
        pSpdTmp->dwSaBytes = pSpd->dwSaBytes;
        pSpdTmp->dwIkeSaId = pSpd->dwIkeSaId;
#endif
        pSpdTmp->dwId = pSpd->dwId;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        pSpdTmp->isGdoi = pSpd->isGdoi;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSpdTmp->dwSrcIPList, pSpd->dwSrcIPList,
                                (MAX_IP_IN_FQDN - 1) * sizeof(MOC_IP_ADDRESS_S));
        gM_DIGI_MEMCPY_ptr(pSpdTmp->dwDestIPList, pSpd->dwDestIPList,
                                (MAX_IP_IN_FQDN - 1) * sizeof(MOC_IP_ADDRESS_S));
#else
        DIGI_MEMCPY(pSpdTmp->dwSrcIPList, pSpd->dwSrcIPList,
                                (MAX_IP_IN_FQDN - 1) * sizeof(MOC_IP_ADDRESS_S));
        DIGI_MEMCPY(pSpdTmp->dwDestIPList, pSpd->dwDestIPList,
                                (MAX_IP_IN_FQDN - 1) * sizeof(MOC_IP_ADDRESS_S));
#endif
        pSpdTmp->dwDestIPCount = pSpd->dwDestIPCount;
        pSpdTmp->dwSrcIPCount = pSpd->dwSrcIPCount;
        pSpdTmp->isUnicastGDOI = pSpd->isUnicastGDOI;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMCPY_ptr(pSpdTmp->fqdn, pSpd->fqdn,
#else
        DIGI_MEMCPY(pSpdTmp->fqdn, pSpd->fqdn,
#endif
                                MOC_MAX_FQDN_LEN );

#endif


    }
    if (i < num) pSpdTmp->flags = 0;

    extDumpData->bufLen = i * sizeof(struct spdCompat);
}

#endif /* !defined(LOADCONFIG_DUMP_TO_STDOUT) */


/*------------------------------------------------------------------*/

#ifdef __KERNEL__
static sbyte4
ipsadm_registerIkeQueue(ExtIkeEventQIoctl_t *extQueue)
{
    sbyte4 status = OK;
    ExtIkeEventQ_t *iqueue = &modStats.ikeQueue;

    struct task_struct *task;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
    task = find_task_by_pid(extQuetidue->tid);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
    task = find_task_by_pid_ns(extQueue->tid, &init_pid_ns);
#else
    /* find_task_by_pid_ns() is no longer EXPORTED */
    rcu_read_lock();
    task = pid_task(find_vpid(extQueue->tid), PIDTYPE_PID);
    rcu_read_unlock();
#endif
    if (!task)
    {
        ERROR_PRINT(("IKE process not found.  pid: %d", extQueue->tid));
        status = -1;
        goto exit;
    }

    DBUG_PRINT(DEBUG_IPSEC, ("Registered from application %d, kaddr=%p", extQueue->tid, extQueue->msgQueue));
    DUMP_LONGS((ubyte *)extQueue, sizeof(*extQueue), 80, "Register message");

    iqueue->tid        = extQueue->tid;
    iqueue->signal     = extQueue->signal;
    iqueue->msgQueue   = (void *)extQueue->msgQueue;

exit:
    return status;
}

#else
ExtIkeEventQ_t extQueue = {0};
static sbyte4
ipsadm_registerIkeQueue(ExtIkeEventQ_t *q)
{
    mqd_t mqdes = -1;

    DBUG_PRINT(DEBUG_IPSEC, ("Registering IKE queue: %s", q->name));
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMSET_ptr((void *)&extQueue, 0, sizeof(ExtIkeEventQ_t));
#else
    DIGI_MEMSET((void *)&extQueue, 0, sizeof(ExtIkeEventQ_t));
#endif

    /* test that we can open up the mq */
    mqdes = mq_open(q->name, O_WRONLY|O_NONBLOCK);
    if (-1 == mqdes)
    {
        ERROR_PRINT(("Failed to open IKE queue %s: %s", q->name,
                     strerror(errno)));
        return -1;
    }
    mq_close(mqdes);

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr((void *)&extQueue, q, sizeof(ExtIkeEventQ_t));
#else
    DIGI_MEMCPY((void *)&extQueue, q, sizeof(ExtIkeEventQ_t));
#endif

    return OK;
}
#endif

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
/*------------------------------------------------------------------*/
#ifdef __KERNEL__
static sbyte4
validate_ifmap(ifmap_entry *ifmap_kern, sbyte4 s)
{
    ifmap_kern->status = s;
    return s;
}
#else
static sbyte4
validate_ifmap(ifmap_entry *ifmap_kern, sbyte4 s)
{
    ifmap_kern->status = s;
    return s;
}
#endif
#endif

#if defined(__KERNEL__)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36))

static sbyte4 ips_copyCompat_ipsecConf1(struct ipsecConf *pConf,
             struct ipsecConfCompat *pCompatConf)
{

    if(!pConf || !pCompatConf)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }
    pConf->dwSrcIP = pCompatConf->dwSrcIP;
    pConf->dwSrcIPEnd = pCompatConf->dwSrcIPEnd;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pConf->dwDestIPList, pCompatConf->dwDestIPList, (pCompatConf->dwDestIPCount) * sizeof(ubyte4));
    pConf->dwDestIPCount = pCompatConf->dwDestIPCount;
    gM_DIGI_MEMCPY_ptr(pConf->dwSrcIPList, pCompatConf->dwSrcIPList, (pCompatConf->dwSrcIPCount) * sizeof(ubyte4));
#else
    DIGI_MEMCPY(pConf->dwDestIPList, pCompatConf->dwDestIPList, (pCompatConf->dwDestIPCount) * sizeof(ubyte4));
    pConf->dwDestIPCount = pCompatConf->dwDestIPCount;
    DIGI_MEMCPY(pConf->dwSrcIPList, pCompatConf->dwSrcIPList, (pCompatConf->dwSrcIPCount) * sizeof(ubyte4));
#endif
    pConf->dwSrcIPCount = pCompatConf->dwSrcIPCount;
#endif
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pConf->wPortList, pCompatConf->wPortList, (pCompatConf->wPortCount) * sizeof(ubyte2));
#else
    DIGI_MEMCPY(pConf->wPortList, pCompatConf->wPortList, (pCompatConf->wPortCount) * sizeof(ubyte2));
#endif
    pConf->wPortCount = pCompatConf->wPortCount;
    pConf->wSrcPort = pCompatConf->wSrcPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
    pConf->wSrcPortEnd = pCompatConf->wSrcPortEnd;
#endif
    pConf->srcPortType = pCompatConf->srcPortType;
    pConf->dwDestIP = pCompatConf->dwDestIP;
    pConf->dwDestIPEnd = pCompatConf->dwDestIPEnd;
    pConf->wDestPort = pCompatConf->wDestPort;
#ifdef __ENABLE_IPSEC_PORT_RANGE__
    pConf->wDestPortEnd = pCompatConf->wDestPortEnd;
#endif
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pConf->wDestPortList, pCompatConf->wDestPortList, (pCompatConf->wDestPortCount) * sizeof(ubyte2));
#else
    DIGI_MEMCPY(pConf->wDestPortList, pCompatConf->wDestPortList, (pCompatConf->wDestPortCount) * sizeof(ubyte2));
#endif
    pConf->wDestPortCount = pCompatConf->wDestPortCount;
    pConf->destPortType = pCompatConf->destPortType;

    pConf->oProto = pCompatConf->oProto;
    pConf->oAction = pCompatConf->oAction;
    pConf->oDir = pCompatConf->oDir;
    pConf->oSaLen = pCompatConf->oSaLen;
    pConf->pxSa = (struct sainfo *)(uintptr_t)pCompatConf->pxSa;

    pConf->oMode = pCompatConf->oMode;
    pConf->dwTunlDestIP = pCompatConf->dwTunlDestIP;
    pConf->dwTunlSrcIP = pCompatConf->dwTunlSrcIP;
    pConf->index = pCompatConf->index;
    pConf->ifid = pCompatConf->ifid;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pConf->cookie = pCompatConf->cookie;
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pConf->dwSaSecs = pCompatConf->dwSaSecs;
    pConf->dwSaBytes = pCompatConf->dwSaBytes;
    pConf->dwIkeSaId = pCompatConf->dwIkeSaId;
#endif
    pConf->flags = pCompatConf->flags;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    pConf->isGdoi = pCompatConf->isGdoi;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pConf->fqdn, pCompatConf->fqdn, MOC_MAX_FQDN_LEN);
#else
    DIGI_MEMCPY(pConf->fqdn, pCompatConf->fqdn, MOC_MAX_FQDN_LEN);
#endif
    pConf->isUnicastGDOI = pCompatConf->isUnicastGDOI;
    pConf->fqdnUniqueKey = pCompatConf->fqdnUniqueKey;
#endif
    return OK;

}

static sbyte4 ips_copyCompat_IpsecConf(ExtIpSecConf_t *pConf,
             ExtIpSecConfCompat_t *pCompatConf)
{

    if(!pConf || !pCompatConf)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }
    ips_copyCompat_ipsecConf1(&(pConf->conf), &(pCompatConf->conf));
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pConf->sa, pCompatConf->sa, 2 * sizeof(struct sainfo));
#else
    DIGI_MEMCPY(pConf->sa, pCompatConf->sa, 2 * sizeof(struct sainfo));
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pConf->srcIP, pCompatConf->srcIP, sizeof(pConf->srcIP));
    gM_DIGI_MEMCPY_ptr(pConf->srcIPend, pCompatConf->srcIPend, sizeof(pConf->srcIPend));
    gM_DIGI_MEMCPY_ptr(pConf->dstIP, pCompatConf->dstIP, sizeof(pConf->dstIP));
    gM_DIGI_MEMCPY_ptr(pConf->dstIPend, pCompatConf->dstIPend, sizeof(pConf->dstIPend));
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    gM_DIGI_MEMCPY_ptr(pConf->tunDstIP, pCompatConf->tunDstIP, sizeof(pConf->tunDstIP));
    gM_DIGI_MEMCPY_ptr(pConf->tunSrcIP, pCompatConf->tunSrcIP, sizeof(pConf->tunSrcIP));
#endif
#else
    DIGI_MEMCPY(pConf->srcIP, pCompatConf->srcIP, sizeof(pConf->srcIP));
    DIGI_MEMCPY(pConf->srcIPend, pCompatConf->srcIPend, sizeof(pConf->srcIPend));
    DIGI_MEMCPY(pConf->dstIP, pCompatConf->dstIP, sizeof(pConf->dstIP));
    DIGI_MEMCPY(pConf->dstIPend, pCompatConf->dstIPend, sizeof(pConf->dstIPend));
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    DIGI_MEMCPY(pConf->tunDstIP, pCompatConf->tunDstIP, sizeof(pConf->tunDstIP));
    DIGI_MEMCPY(pConf->tunSrcIP, pCompatConf->tunSrcIP, sizeof(pConf->tunSrcIP));
#endif
#endif
#endif
#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
    pConf->rekeyForever = pCompatConf->rekeyForever;
#endif

    return 0;
}

static sbyte4 ips_copyCompat_ipsecKey1(struct ipsecKey *pKey,
             struct ipsecKeyCompat *pCompatKey)
{

    if(!pKey || !pCompatKey)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }

    pKey->oProtocol = pCompatKey->oProtocol;
    pKey->dwSpi = pCompatKey->dwSpi;
    pKey->dwDestAddr = pCompatKey->dwDestAddr;
    pKey->dwSrcAddr = pCompatKey->dwSrcAddr;
#ifdef __ENABLE_IPSEC_NAT_T__
    pKey->wUdpEncPort = pCompatKey->wUdpEncPort;
#endif
    pKey->oMode = pCompatKey->oMode;
    pKey->oAuthAlgo = pCompatKey->oAuthAlgo;
    pKey->pAuthKey = (sbyte *)(uintptr_t)pCompatKey->pAuthKey;
    pKey->wAuthKeyLen = pCompatKey->wAuthKeyLen;
    pKey->oEncrAlgo = pCompatKey->oEncrAlgo;
    pKey->pEncrKey = (sbyte *)(uintptr_t)pCompatKey->pEncrKey;
    pKey->wEncrKeyLen = pCompatKey->wEncrKeyLen;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    pKey->oNonceLen = pCompatKey->oNonceLen;
    pKey->oAeadIcvLen = pCompatKey->oAeadIcvLen;
    pKey->dwExpSecs = pCompatKey->dwExpSecs;
    pKey->dwExpKBytes = pCompatKey->dwExpKBytes;
#endif
    pKey->wDestPort = pCompatKey->wDestPort;
    pKey->wSrcPort = pCompatKey->wSrcPort;
    pKey->oUlp = pCompatKey->oUlp;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pKey->cookie = pCompatKey->cookie;
#endif
    pKey->dwSeqNo = pCompatKey->dwSeqNo;
    pKey->flags = pCompatKey->flags;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pKey->dwIkeSaId = pCompatKey->dwIkeSaId;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pKey->ifid = pCompatKey->ifid;
#endif
#endif
    pKey->status = pCompatKey->status;
    return 0;

}


static sbyte4 ips_copyCompat_IpsecKey(ExtIpSecKey_t *pKey,
             ExtIpSecKeyCompat_t *pCompatKey)
{

    if(!pKey || !pCompatKey)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }

    pKey->key.oProtocol = pCompatKey->key.oProtocol;
    pKey->key.dwSpi = pCompatKey->key.dwSpi;
    pKey->key.dwDestAddr = pCompatKey->key.dwDestAddr;
    pKey->key.dwSrcAddr = pCompatKey->key.dwSrcAddr;
#ifdef __ENABLE_IPSEC_NAT_T__
    pKey->key.wUdpEncPort = pCompatKey->key.wUdpEncPort;
#endif
    pKey->key.oMode = pCompatKey->key.oMode;
    pKey->key.oAuthAlgo = pCompatKey->key.oAuthAlgo;
    pKey->key.pAuthKey = (sbyte *)(uintptr_t)pCompatKey->key.pAuthKey;
    pKey->key.wAuthKeyLen = pCompatKey->key.wAuthKeyLen;
    pKey->key.oEncrAlgo = pCompatKey->key.oEncrAlgo;
    pKey->key.pEncrKey = (sbyte *)(uintptr_t)pCompatKey->key.pEncrKey;
    pKey->key.wEncrKeyLen = pCompatKey->key.wEncrKeyLen;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    pKey->key.oNonceLen = pCompatKey->key.oNonceLen;
    pKey->key.oAeadIcvLen = pCompatKey->key.oAeadIcvLen;
    pKey->key.dwExpSecs = pCompatKey->key.dwExpSecs;
    pKey->key.dwExpKBytes = pCompatKey->key.dwExpKBytes;
#endif
    pKey->key.wDestPort = pCompatKey->key.wDestPort;
    pKey->key.wSrcPort = pCompatKey->key.wSrcPort;
    pKey->key.oUlp = pCompatKey->key.oUlp;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pKey->key.cookie = pCompatKey->key.cookie;
#endif
    pKey->key.dwSeqNo = pCompatKey->key.dwSeqNo;
    pKey->key.flags = pCompatKey->key.flags;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pKey->key.dwIkeSaId = pCompatKey->key.dwIkeSaId;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pKey->key.ifid = pCompatKey->key.ifid;
#endif
#endif
    pKey->key.status = pCompatKey->key.status;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pKey->authKey, pCompatKey->authKey, sizeof(pKey->authKey));
    gM_DIGI_MEMCPY_ptr(pKey->encrKey, pCompatKey->encrKey, sizeof(pKey->encrKey));
#ifdef __ENABLE_DIGICERT_IPV6__
    gM_DIGI_MEMCPY_ptr(pKey->dstAddr, pCompatKey->dstAddr, sizeof(pKey->dstAddr));
    gM_DIGI_MEMCPY_ptr(pKey->srcAddr, pCompatKey->srcAddr, sizeof(pKey->srcAddr));
#endif
#else
    DIGI_MEMCPY(pKey->authKey, pCompatKey->authKey, sizeof(pKey->authKey));
    DIGI_MEMCPY(pKey->encrKey, pCompatKey->encrKey, sizeof(pKey->encrKey));
#ifdef __ENABLE_DIGICERT_IPV6__
    DIGI_MEMCPY(pKey->dstAddr, pCompatKey->dstAddr, sizeof(pKey->dstAddr));
    DIGI_MEMCPY(pKey->srcAddr, pCompatKey->srcAddr, sizeof(pKey->srcAddr));
#endif
#endif
    return 0;

}

static sbyte4 ips_IpsecKey_copyToCompat(ExtIpSecKey_t *pKey,
             ExtIpSecKeyCompat_t *pCompatKey)
{

    if(!pKey || !pCompatKey)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }

    pCompatKey->key.oProtocol = pKey->key.oProtocol;
    pCompatKey->key.dwSpi = pKey->key.dwSpi;
    pCompatKey->key.dwDestAddr = pKey->key.dwDestAddr;
    pCompatKey->key.dwSrcAddr = pKey->key.dwSrcAddr;
#ifdef __ENABLE_IPSEC_NAT_T__
    pCompatKey->key.wUdpEncPort = pKey->key.wUdpEncPort;
#endif
    pCompatKey->key.oMode = pKey->key.oMode;
    pCompatKey->key.oAuthAlgo = pKey->key.oAuthAlgo;
    pCompatKey->key.pAuthKey = (ubyte4)(uintptr_t)pKey->key.pAuthKey;
    pCompatKey->key.wAuthKeyLen = pKey->key.wAuthKeyLen;
    pCompatKey->key.oEncrAlgo = pKey->key.oEncrAlgo;
    pCompatKey->key.pEncrKey = (ubyte4)(uintptr_t)pKey->key.pEncrKey;
    pCompatKey->key.wEncrKeyLen = pKey->key.wEncrKeyLen;
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    pCompatKey->key.oNonceLen = pKey->key.oNonceLen;
    pCompatKey->key.oAeadIcvLen = pKey->key.oAeadIcvLen;
    pCompatKey->key.dwExpSecs = pKey->key.dwExpSecs;
    pCompatKey->key.dwExpKBytes = pKey->key.dwExpKBytes;
#endif
    pCompatKey->key.wDestPort = pKey->key.wDestPort;
    pCompatKey->key.wSrcPort = pKey->key.wSrcPort;
    pCompatKey->key.oUlp = pKey->key.oUlp;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pCompatKey->key.cookie = pKey->key.cookie;
#endif
    pCompatKey->key.dwSeqNo = pKey->key.dwSeqNo;
    pCompatKey->key.flags = pKey->key.flags;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pCompatKey->key.dwIkeSaId = pKey->key.dwIkeSaId;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pCompatKey->key.ifid = pKey->key.ifid;
#endif
#endif
    pCompatKey->key.status = pKey->key.status;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pCompatKey->authKey, pKey->authKey, sizeof(pCompatKey->authKey));
    gM_DIGI_MEMCPY_ptr(pCompatKey->encrKey, pKey->encrKey, sizeof(pCompatKey->encrKey));
#ifdef __ENABLE_DIGICERT_IPV6__
    gM_DIGI_MEMCPY_ptr(pCompatKey->dstAddr, pKey->dstAddr, sizeof(pCompatKey->dstAddr));
    gM_DIGI_MEMCPY_ptr(pCompatKey->srcAddr, pKey->srcAddr, sizeof(pCompatKey->srcAddr));
#endif
#else
    DIGI_MEMCPY(pCompatKey->authKey, pKey->authKey, sizeof(pCompatKey->authKey));
    DIGI_MEMCPY(pCompatKey->encrKey, pKey->encrKey, sizeof(pCompatKey->encrKey));
#ifdef __ENABLE_DIGICERT_IPV6__
    DIGI_MEMCPY(pCompatKey->dstAddr, pKey->dstAddr, sizeof(pCompatKey->dstAddr));
    DIGI_MEMCPY(pCompatKey->srcAddr, pKey->srcAddr, sizeof(pCompatKey->srcAddr));
#endif
#endif
    return 0;

}


static sbyte4 ips_copyCompat_ipsecKeyEx1(struct ipsecKeyEx *pKey,
             struct ipsecKeyExCompat *pCompatKey)
{

    if(!pKey || !pCompatKey)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }

    pKey->flags = pCompatKey->flags;
    pKey->oProtocol = pCompatKey->oProtocol;
    pKey->dwSpi = pCompatKey->dwSpi;
    pKey->dwDestAddr = (MOC_IP_ADDRESS)pCompatKey->dwDestAddr;
    pKey->dwSrcAddr = (MOC_IP_ADDRESS)pCompatKey->dwSrcAddr;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pKey->cookie = pCompatKey->cookie;
#endif
#if 1 /* def __ENABLE_IPSEC_NAT_T__ */
    pKey->wUdpEncPort = pCompatKey->wUdpEncPort;
#endif
    pKey->wDestPort = pCompatKey->wDestPort;
    pKey->wSrcPort = pCompatKey->wSrcPort;
    pKey->oUlp = pCompatKey->oUlp;
    pKey->oMode = pCompatKey->oMode;
    pKey->dwDestIP = (MOC_IP_ADDRESS)pCompatKey->dwDestIP;
    pKey->dwDestIPEnd = (MOC_IP_ADDRESS)pCompatKey->dwDestIPEnd;
    pKey->dwSrcIP = (MOC_IP_ADDRESS)pCompatKey->dwSrcIP;
    pKey->dwSrcIPEnd = (MOC_IP_ADDRESS)pCompatKey->dwSrcIPEnd;



    pKey->oAuthAlgo = pCompatKey->oAuthAlgo;
    pKey->poAuthKey = (sbyte *)(uintptr_t)pCompatKey->poAuthKey;
    pKey->wAuthKeyLen = pCompatKey->wAuthKeyLen;
    pKey->oEncrAlgo = pCompatKey->oEncrAlgo;
    pKey->poEncrKey = (sbyte *)(uintptr_t)pCompatKey->poEncrKey;
    pKey->wEncrKeyLen = pCompatKey->wEncrKeyLen;
    pKey->oNonceLen = pCompatKey->oNonceLen;
    pKey->oAeadIcvLen = pCompatKey->oAeadIcvLen;
    pKey->dwExpSecs = pCompatKey->dwExpSecs;
    pKey->dwExpKBytes = pCompatKey->dwExpKBytes;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pKey->dwSpiM = pCompatKey->dwSpiM;
    pKey->spdIndex = pCompatKey->spdIndex;
    pKey->dwSpdId = pCompatKey->dwSpdId;
    pKey->iNest = pCompatKey->iNest;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pKey->ifid = pCompatKey->ifid;
#endif

    pKey->dwIkeSaId = pCompatKey->dwIkeSaId;
    pKey->ikeSaLoc = pCompatKey->ikeSaLoc;
    pKey->dwTimeStart = pCompatKey->dwTimeStart;

#ifdef __ENABLE_DIGICERT_PFKEY__
    pKey->sadb_msg_seq = pCompatKey->sadb_msg_seq;
    pKey->sadb_sa_replay = pCompatKey->sadb_sa_replay;
#endif
#ifdef __ENABLE_DIGICERT_IPCOMP__
    pKey->oCompAlgo = pCompatKey->oCompAlgo;
    pKey->wCpi = pCompatKey->wCpi;
    pKey->wCpiM = pCompatKey->wCpiM;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pKey->dwDestAddrList, pCompatKey->dwDestAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->dwDestAddrCount = pCompatKey->dwDestAddrCount;
    gM_DIGI_MEMCPY_ptr(pKey->dwSrcAddrList, pCompatKey->dwSrcAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->dwSrcAddrCount = pCompatKey->dwSrcAddrCount;
    gM_DIGI_MEMCPY_ptr(pKey->fqdn, pCompatKey->fqdn, MOC_MAX_FQDN_LEN);
#else
    DIGI_MEMCPY(pKey->dwDestAddrList, pCompatKey->dwDestAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->dwDestAddrCount = pCompatKey->dwDestAddrCount;
    DIGI_MEMCPY(pKey->dwSrcAddrList, pCompatKey->dwSrcAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->dwSrcAddrCount = pCompatKey->dwSrcAddrCount;
    DIGI_MEMCPY(pKey->fqdn, pCompatKey->fqdn, MOC_MAX_FQDN_LEN);
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    pKey->fqdnUniqueKey = pCompatKey->fqdnUniqueKey;
#endif
#endif
    pKey->inbound = pCompatKey->inbound;

#endif
    return 0;

}

static sbyte4 ips_copyCompat_IpsecKeyEx(ExtIpSecKeyEx_t *pKey,
             ExtIpSecKeyExCompat_t *pCompatKey)
{

    if(!pKey || !pCompatKey)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }

    pKey->key.flags = pCompatKey->key.flags;
    pKey->key.oProtocol = pCompatKey->key.oProtocol;
    pKey->key.dwSpi = pCompatKey->key.dwSpi;
    pKey->key.dwDestAddr = (MOC_IP_ADDRESS)pCompatKey->key.dwDestAddr;
    pKey->key.dwSrcAddr = (MOC_IP_ADDRESS)pCompatKey->key.dwSrcAddr;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pKey->key.cookie = pCompatKey->key.cookie;
#endif
#if 1 /* def __ENABLE_IPSEC_NAT_T__ */
    pKey->key.wUdpEncPort = pCompatKey->key.wUdpEncPort;
#endif
    pKey->key.wDestPort = pCompatKey->key.wDestPort;
    pKey->key.wSrcPort = pCompatKey->key.wSrcPort;
    pKey->key.oUlp = pCompatKey->key.oUlp;
    pKey->key.oMode = pCompatKey->key.oMode;
    pKey->key.dwDestIP = (MOC_IP_ADDRESS)pCompatKey->key.dwDestIP;
    pKey->key.dwDestIPEnd = (MOC_IP_ADDRESS)pCompatKey->key.dwDestIPEnd;
    pKey->key.dwSrcIP = (MOC_IP_ADDRESS)pCompatKey->key.dwSrcIP;
    pKey->key.dwSrcIPEnd = (MOC_IP_ADDRESS)pCompatKey->key.dwSrcIPEnd;



    pKey->key.oAuthAlgo = pCompatKey->key.oAuthAlgo;
    pKey->key.poAuthKey = (sbyte *)(uintptr_t)pCompatKey->key.poAuthKey;
    pKey->key.wAuthKeyLen = pCompatKey->key.wAuthKeyLen;
    pKey->key.oEncrAlgo = pCompatKey->key.oEncrAlgo;
    pKey->key.poEncrKey = (sbyte *)(uintptr_t)pCompatKey->key.poEncrKey;
    pKey->key.wEncrKeyLen = pCompatKey->key.wEncrKeyLen;
    pKey->key.oNonceLen = pCompatKey->key.oNonceLen;
    pKey->key.oAeadIcvLen = pCompatKey->key.oAeadIcvLen;
    pKey->key.dwExpSecs = pCompatKey->key.dwExpSecs;
    pKey->key.dwExpKBytes = pCompatKey->key.dwExpKBytes;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pKey->key.dwSpiM = pCompatKey->key.dwSpiM;
    pKey->key.spdIndex = pCompatKey->key.spdIndex;
    pKey->key.dwSpdId = pCompatKey->key.dwSpdId;
    pKey->key.iNest = pCompatKey->key.iNest;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pKey->key.ifid = pCompatKey->key.ifid;
#endif

    pKey->key.dwIkeSaId = pCompatKey->key.dwIkeSaId;
    pKey->key.ikeSaLoc = pCompatKey->key.ikeSaLoc;
    pKey->key.dwTimeStart = pCompatKey->key.dwTimeStart;

#ifdef __ENABLE_DIGICERT_PFKEY__
    pKey->key.sadb_msg_seq = pCompatKey->key.sadb_msg_seq;
    pKey->key.sadb_sa_replay = pCompatKey->key.sadb_sa_replay;
#endif
#ifdef __ENABLE_DIGICERT_IPCOMP__
    pKey->key.oCompAlgo = pCompatKey->key.oCompAlgo;
    pKey->key.wCpi = pCompatKey->key.wCpi;
    pKey->key.wCpiM = pCompatKey->key.wCpiM;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pKey->key.dwDestAddrList, pCompatKey->key.dwDestAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->key.dwDestAddrCount = pCompatKey->key.dwDestAddrCount;
    gM_DIGI_MEMCPY_ptr(pKey->key.dwSrcAddrList, pCompatKey->key.dwSrcAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->key.dwSrcAddrCount = pCompatKey->key.dwSrcAddrCount;
    gM_DIGI_MEMCPY_ptr(pKey->key.fqdn, pCompatKey->key.fqdn, MOC_MAX_FQDN_LEN);
#else
    DIGI_MEMCPY(pKey->key.dwDestAddrList, pCompatKey->key.dwDestAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->key.dwDestAddrCount = pCompatKey->key.dwDestAddrCount;
    DIGI_MEMCPY(pKey->key.dwSrcAddrList, pCompatKey->key.dwSrcAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pKey->key.dwSrcAddrCount = pCompatKey->key.dwSrcAddrCount;
    DIGI_MEMCPY(pKey->key.fqdn, pCompatKey->key.fqdn, MOC_MAX_FQDN_LEN);
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    pKey->key.fqdnUniqueKey = pCompatKey->key.fqdnUniqueKey;
#endif
#endif
    pKey->key.inbound = pCompatKey->key.inbound;

#endif
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pKey->authKey, pCompatKey->authKey, sizeof(pKey->authKey));
    gM_DIGI_MEMCPY_ptr(pKey->encrKey, pCompatKey->encrKey, sizeof(pKey->encrKey));
#else
    DIGI_MEMCPY(pKey->authKey, pCompatKey->authKey, sizeof(pKey->authKey));
    DIGI_MEMCPY(pKey->encrKey, pCompatKey->encrKey, sizeof(pKey->encrKey));
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
    pKey->dstAddr = pCompatKey->dstAddr;
    pKey->srcAddr = pCompatKey->srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    pKey->dstIP = pCompatKey->dstIP;
    pKey->dstIPend = pCompatKey->dstIPend;
    pKey->srcIP = pCompatKey->srcIP;
    pKey->srcIPend = pCompatKey->srcIPend;
#endif
#endif
    return 0;

}

#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
static sbyte4 ips_IpsecKeyEx_copyToCompat(ExtIpSecKeyEx_t *pKey,
             ExtIpSecKeyExCompat_t *pCompatKey)
{

    if(!pKey || !pCompatKey)
    {
        ERROR_PRINT(("NULL pointer"));
        return -1;
    }

    pCompatKey->key.flags = pKey->key.flags;
    pCompatKey->key.oProtocol = pKey->key.oProtocol;
    pCompatKey->key.dwSpi = pKey->key.dwSpi;
    pCompatKey->key.dwDestAddr = pKey->key.dwDestAddr;
    pCompatKey->key.dwSrcAddr = pKey->key.dwSrcAddr;
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pCompatKey->key.cookie = pKey->key.cookie;
#endif
#if 1 /* def __ENABLE_IPSEC_NAT_T__ */
    pCompatKey->key.wUdpEncPort = pKey->key.wUdpEncPort;
#endif
    pCompatKey->key.wDestPort = pKey->key.wDestPort;
    pCompatKey->key.wSrcPort = pKey->key.wSrcPort;
    pCompatKey->key.oUlp = pKey->key.oUlp;
    pCompatKey->key.oMode = pKey->key.oMode;
    pCompatKey->key.dwDestIP = pKey->key.dwDestIP;
    pCompatKey->key.dwDestIPEnd = pKey->key.dwDestIPEnd;
    pCompatKey->key.dwSrcIP = pKey->key.dwSrcIP;
    pCompatKey->key.dwSrcIPEnd = pKey->key.dwSrcIPEnd;



    pCompatKey->key.oAuthAlgo = pKey->key.oAuthAlgo;
    pCompatKey->key.poAuthKey = (ubyte4)(uintptr_t)pKey->key.poAuthKey;
    pCompatKey->key.wAuthKeyLen = pKey->key.wAuthKeyLen;
    pCompatKey->key.oEncrAlgo = pKey->key.oEncrAlgo;
    pCompatKey->key.poEncrKey = (ubyte4)(uintptr_t)pKey->key.poEncrKey;
    pCompatKey->key.wEncrKeyLen = pKey->key.wEncrKeyLen;
    pCompatKey->key.oNonceLen = pKey->key.oNonceLen;
    pCompatKey->key.oAeadIcvLen = pKey->key.oAeadIcvLen;
    pCompatKey->key.dwExpSecs = pKey->key.dwExpSecs;
    pCompatKey->key.dwExpKBytes = pKey->key.dwExpKBytes;
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    pCompatKey->key.dwSpiM = pKey->key.dwSpiM;
    pCompatKey->key.spdIndex = pKey->key.spdIndex;
    pCompatKey->key.dwSpdId = pKey->key.dwSpdId;
    pCompatKey->key.iNest = pKey->key.iNest;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pCompatKey->key.ifid = pKey->key.ifid;
#endif

    pCompatKey->key.dwIkeSaId = pKey->key.dwIkeSaId;
    pCompatKey->key.ikeSaLoc = pKey->key.ikeSaLoc;
    pCompatKey->key.dwTimeStart = pKey->key.dwTimeStart;

#ifdef __ENABLE_DIGICERT_PFKEY__
    pCompatKey->key.sadb_msg_seq = pKey->key.sadb_msg_seq;
    pCompatKey->key.sadb_sa_replay = pKey->key.sadb_sa_replay;
#endif
#ifdef __ENABLE_DIGICERT_IPCOMP__
    pCompatKey->key.oCompAlgo = pKey->key.oCompAlgo;
    pCompatKey->key.wCpi = pKey->key.wCpi;
    pCompatKey->key.wCpiM = pKey->key.wCpiM;
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pCompatKey->key.dwDestAddrList, pKey->key.dwDestAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pCompatKey->key.dwDestAddrCount = pKey->key.dwDestAddrCount;
    gM_DIGI_MEMCPY_ptr(pCompatKey->key.dwSrcAddrList, pKey->key.dwSrcAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pCompatKey->key.dwSrcAddrCount = pKey->key.dwSrcAddrCount;
    gM_DIGI_MEMCPY_ptr(pCompatKey->key.fqdn, pKey->key.fqdn, MOC_MAX_FQDN_LEN);
#else
    DIGI_MEMCPY(pCompatKey->key.dwDestAddrList, pKey->key.dwDestAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pCompatKey->key.dwDestAddrCount = pKey->key.dwDestAddrCount;
    DIGI_MEMCPY(pCompatKey->key.dwSrcAddrList, pKey->key.dwSrcAddrList, MAX_IP_IN_FQDN * sizeof(ubyte4));
    pCompatKey->key.dwSrcAddrCount = pKey->key.dwSrcAddrCount;
    DIGI_MEMCPY(pCompatKey->key.fqdn, pKey->key.fqdn, MOC_MAX_FQDN_LEN);
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    pCompatKey->key.fqdnUniqueKey = pKey->key.fqdnUniqueKey;
#endif
#endif
    pCompatKey->key.inbound = pKey->key.inbound;

#endif
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    gM_DIGI_MEMCPY_ptr(pCompatKey->authKey, pKey->authKey, sizeof(pCompatKey->authKey));
    gM_DIGI_MEMCPY_ptr(pCompatKey->encrKey, pKey->encrKey, sizeof(pCompatKey->encrKey));
#else
    DIGI_MEMCPY(pCompatKey->authKey, pKey->authKey, sizeof(pCompatKey->authKey));
    DIGI_MEMCPY(pCompatKey->encrKey, pKey->encrKey, sizeof(pCompatKey->encrKey));
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
    pCompatKey->dstAddr = pKey->dstAddr;
    pCompatKey->srcAddr = pKey->srcAddr;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    pCompatKey->dstIP = pKey->dstIP;
    pCompatKey->dstIPend = pKey->dstIPend;
    pCompatKey->srcIP = pKey->srcIP;
    pCompatKey->srcIPend = pKey->srcIPend;
#endif
#endif
    return 0;

}
#endif


extern long
ipsec_compat_ioctl(struct file *file,
            unsigned int cmd, unsigned long arg)
{
    int value, status = 0;

    if (0 != copy_from_user(&value, (void __user *)arg, sizeof(value)))
    {
        status = -1;
        return status;
    }
    DBUG_PRINT(DEBUG_IPSEC, ("cmd = 0x%x, value = 0x%08x", cmd, value));

    switch (cmd)
    {
    case IOC_DUMP_STATS:
        ips_dumpStats(value);
        DBUG_PRINT(DEBUG_IPSEC, ("Sizeof ipsecConf = %d", sizeof(struct ipsecConf)));
        break;

    case IOC_ENABLE:
        modStats.active = value;
        break;

    case IOC_TRACE:
        modStats.trace = value;
        ips_dumpStats(0);
        break;

    case IOC_SET_RUNFLAGS:
        modStats.runFlags = value;
        ips_dumpStats(0);
        break;

    case IOC_ADD_KEY:
    {
        ExtIpSecKeyCompat_t compatKey;
        static ExtIpSecKey_t key;
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#else
            DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#endif
            ips_copyCompat_IpsecKey(&key, &compatKey);
            status = ipsadm_addKey(&key);
            compatKey.key.status = key.key.status;
            if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
    case IOC_ADD_KEY_EX:
    {
        ExtIpSecKeyExCompat_t compatKey;
        static ExtIpSecKeyEx_t key;
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKeyEx_t));
#else
            DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKeyEx_t));
#endif
            ips_copyCompat_IpsecKeyEx(&key, &compatKey);
            status = ipsadm_addKeyEx(&key);
            compatKey.key.spdIndex = key.key.spdIndex;
            compatKey.key.dwSpdId = key.key.dwSpdId;
            if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
    case IOC_KEY_READY:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        static ExtIpSecKeyEx_t key;
        ExtIpSecKeyExCompat_t compatKey;
#else
        static struct ipsecKeyEx key;
        struct ipsecKeyExCompat compatKey;
#endif
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_IPV6__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKeyEx_t));
#else
            DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKeyEx_t));
#endif

            ips_copyCompat_IpsecKeyEx(&key, &compatKey);
            status = ipsadm_readyKey(&key);
            compatKey.key.spdIndex = key.key.spdIndex;
            compatKey.key.dwSpdId = key.key.dwSpdId;
            compatKey.key.dwExpSecs = key.key.dwExpSecs;
            compatKey.key.dwExpKBytes = key.key.dwExpKBytes;
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(struct ipsecKeyEx));
#else
            DIGI_MEMSET((ubyte *)&key, 0, sizeof(struct ipsecKeyEx));
#endif
            ips_copyCompat_ipsecKeyEx1(&key, &compatKey);
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            status = gM_IPSEC_keyReady_ptr(&key);
#else
            status = IPSEC_keyReady(&key);
#endif
            compatKey.spdIndex = key.spdIndex;
            compatKey.dwSpdId = key.dwSpdId;
            compatKey.dwExpSecs = key.dwExpSecs;
            compatKey.dwExpKBytes = key.dwExpKBytes;
#endif
            if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
    case IOC_DEL_KEY:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        IPSECKEY keyData;
#endif
        ubyte4 dwSpi;
#ifdef __ENABLE_DIGICERT_IPV6__
        static ExtIpSecKey_t key;
        ExtIpSecKeyCompat_t compatKey;
        ExtIpSecKey_t *keyInfo = &key;
#else
        static struct ipsecKey key;
        struct ipsecKeyCompat compatKey;
#endif
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
            break;
        }
#ifdef __ENABLE_DIGICERT_IPV6__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#else
        DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#endif

        ips_copyCompat_IpsecKey(&key, &compatKey);
        keyData = &keyInfo->key;
        dwSpi = keyData->dwSpi;

        if (IPSEC_SA_FLAG_IP6 & keyData->flags)
        {
            if (keyData->dwDestAddr)
                keyData->dwDestAddr = (CAST_MOC_IPADDR) keyInfo->dstAddr;
            if (keyData->dwSrcAddr)
                keyData->dwSrcAddr = (CAST_MOC_IPADDR) keyInfo->srcAddr;
        }
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyDelete_ptr(keyData);
#else
        status = IPSEC_keyDelete(keyData);
#endif
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(struct ipsecKey));
#else
        DIGI_MEMSET((ubyte *)&key, 0, sizeof(struct ipsecKey));
#endif
        ips_copyCompat_ipsecKey1(&key, &compatKey);
        dwSpi = key.dwSpi;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyDelete_ptr(&key);
#else
        status = IPSEC_keyDelete(&key);
#endif
#endif
        /*DUMP_LONGS((ubyte *)keyData, sizeof(*keyData), 80, "Key Delete Info");*/

        if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
        {
            if (0 <= status) status = -1;
        }
        if (OK > status)
        {
            ERROR_PRINT(("Error deleting key (spi=%x): status=%d", dwSpi, status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Key (spi=%x) deleted", dwSpi));
        break;
    }
    case IOC_KEY_INIT:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        IPSECKEY keyData;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        static ExtIpSecKey_t key;
        ExtIpSecKeyCompat_t compatKey;
        ExtIpSecKey_t *keyInfo = &key;
#else
        static struct ipsecKey key;
        struct ipsecKeyCompat compatKey;
#endif
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
            break;
        }
#ifndef __ENABLE_DIGICERT_IPV6__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(struct ipsecKey));
        ips_copyCompat_ipsecKey1(&key, &compatKey);
        status = gM_IPSEC_keyInitiate_ptr(&key);
#else
        DIGI_MEMSET((ubyte *)&key, 0, sizeof(struct ipsecKey));
        ips_copyCompat_ipsecKey1(&key, &compatKey);
        status = IPSEC_keyInitiate(&key);
#endif
#else

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#else
        DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#endif
        ips_copyCompat_IpsecKey(&key, &compatKey);
        keyData = &keyInfo->key;

        if (IPSEC_SA_FLAG_IP6 & keyData->flags)
        {
            if (keyData->dwDestAddr)
                keyData->dwDestAddr = (CAST_MOC_IPADDR) keyInfo->dstAddr;
            if (keyData->dwSrcAddr)
                keyData->dwSrcAddr = (CAST_MOC_IPADDR) keyInfo->srcAddr;
        }

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyInitiate_ptr(keyData);
#else
        status = IPSEC_keyInitiate(keyData);
#endif
#endif
        if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
        {
            if (0 <= status) status = -1;
        }
        break;
    }
#ifdef __ENABLE_MOBIKE__
    case IOC_KEY_UPDATE:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        IPSECKEY keyData;
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
        static ExtIpSecKey_t key;
        ExtIpSecKeyCompat_t compatKey;
        ExtIpSecKey_t *keyInfo = &key;
#else
        static struct ipsecKey key;
        struct ipsecKeyCompat compatKey;
#endif
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
            break;
        }
#ifndef __ENABLE_DIGICERT_IPV6__

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(struct ipsecKey));
#else
        DIGI_MEMSET((ubyte *)&key, 0, sizeof(struct ipsecKey));
#endif
        ips_copyCompat_ipsecKey1(&key, &compatKey);
        status = IPSEC_keyUpdate(&key);
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#else
        DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#endif
        ips_copyCompat_IpsecKey(&key, &compatKey);
        keyData = &keyInfo->key;

        if (IPSEC_SA_FLAG_IP6 & keyData->flags)
        {
            if (keyData->dwDestAddr)
                keyData->dwDestAddr = (CAST_MOC_IPADDR) keyInfo->dstAddr;
            if (keyData->dwSrcAddr)
                keyData->dwSrcAddr = (CAST_MOC_IPADDR) keyInfo->srcAddr;
        }

        status = IPSEC_keyUpdate(keyData);
#endif
        if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
        {
            if (0 <= status) status = -1;
        }
        break;
    }
#endif
    case IOC_GET_KEY:
    {
        static ExtIpSecKey_t key;
        ExtIpSecKeyCompat_t compatKey;
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#else
            DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKey_t));
#endif

            ips_copyCompat_IpsecKey(&key, &compatKey);
            status = ipsadm_getKey(&key);
            ips_IpsecKey_copyToCompat(&key, &compatKey);
            if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    case IOC_GET_KEY_EX:
    {
        static ExtIpSecKeyEx_t key;
        ExtIpSecKeyExCompat_t compatKey;
        if (0 != copy_from_user(&compatKey, (void __user *)arg, sizeof(compatKey)))
        {
            status = -1;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&key, 0, sizeof(ExtIpSecKeyEx_t));
#else
            DIGI_MEMSET((ubyte *)&key, 0, sizeof(ExtIpSecKeyEx_t));
#endif
            ips_copyCompat_IpsecKeyEx(&key, &compatKey);
            status = ipsadm_getKeyEx(&key);
            ips_IpsecKeyEx_copyToCompat(&key, &compatKey);
            if (0 != copy_to_user((void __user *)arg, &compatKey, sizeof(compatKey)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
#endif
    case IOC_FLUSH_SA:
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        if (OK > (status = gM_IPSEC_keyFlush_ptr()))
#else
        if (OK > (status = IPSEC_keyFlush()))
#endif
        {
            ERROR_PRINT(("Error flushing key: status=%d", status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Keys flushed"));
        break;

    case IOC_DUMP_SA:
    {
#if !defined(LOADCONFIG_DUMP_TO_STDOUT)
        ipsadm_dumpSA(value);
#else
        static ubyte sadbBuf[sizeof(ExtIpSecDump_t) +
                             (128 * sizeof(struct sadbCompat))] = { 0 };
        ExtIpSecDump_t *ioBuf = (ExtIpSecDump_t *)sadbBuf;
        if (0 != copy_from_user(ioBuf, (void __user *)arg, sizeof(*ioBuf)))
        {
            status = -1;
        }
        else
        {
            ioBuf->bufLen = 128 * sizeof(struct sadbCompat);
            ipsadm_dumpSA_compat(ioBuf);
            if (0 != copy_to_user((void __user *) ((ExtIpSecDump_t *)arg)->pBuf,
                                  ioBuf->pBuf, ioBuf->bufLen) ||
                0 != copy_to_user((void __user *)arg, ioBuf, sizeof(*ioBuf)))
            {
                status = -1;
            }
        }
#endif
        break;
    }
    case IOC_GET_SADB_SIZE:
    {
        int size = sizeof(struct sadbCompat);
        if (0 != copy_to_user((void __user *)arg, &size, sizeof(size)))
        {
            status = -1;
        }
        break;
    }
    case IOC_ADD_CONF:
    {
        static ExtIpSecConf_t conf;
        ExtIpSecConfCompat_t confCompat;
        if (0 != copy_from_user(&confCompat, (void __user *)arg, sizeof(confCompat)))
        {
            status = -1;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&conf, 0, sizeof(ExtIpSecConf_t));
#else
            DIGI_MEMSET((ubyte *)&conf, 0, sizeof(ExtIpSecConf_t));
#endif
            ips_copyCompat_IpsecConf(&conf, &confCompat);
            status = ipsadm_addConf(&conf);
            confCompat.conf.index = conf.conf.index;
            if (0 != copy_to_user((void __user *)arg, &confCompat, sizeof(confCompat)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
    case IOC_DEL_CONF:
    {
        static struct ipsecConf conf;
        struct ipsecConfCompat confCompat;
        if (0 != copy_from_user(&confCompat, (void __user *)arg, sizeof(confCompat)))
        {
            status = -1;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGI_MEMSET_ptr((ubyte *)&conf, 0, sizeof(struct ipsecConf));
#else
            DIGI_MEMSET((ubyte *)&conf, 0, sizeof(struct ipsecConf));
#endif
            ips_copyCompat_ipsecConf1(&conf, &confCompat);
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            status = gM_IPSEC_confDelete_ptr(&conf);
#else
            status = IPSEC_confDelete(&conf);
#endif
            if (0 != copy_to_user((void __user *)arg, &confCompat, sizeof(confCompat)))
            {
                if (0 <= status) status = -1;
            }
        }
        if (OK > status)
        {
            ERROR_PRINT(("Error deleting policy: status=%d", status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Policy deleted"));
        break;
    }
    case IOC_FLUSH_SPD:

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        if (OK > (status = gM_IPSEC_confFlush_ptr()))
#else
        if (OK > (status = IPSEC_confFlush()))
#endif
        {
            ERROR_PRINT(("Error flushing configs: status=%d", status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Config flushed"));
        break;
    case IOC_DUMP_SPD:
    {
#if !defined(LOADCONFIG_DUMP_TO_STDOUT)
        ipsadm_dumpSPD(value);
#else
        static ubyte spdBuf[sizeof(ExtIpSecDump_t) +
                            (64 * sizeof(struct spdCompat))] = { 0 };
        ExtIpSecDump_t *ioBuf = (ExtIpSecDump_t *)spdBuf;;
        if (0 != copy_from_user(ioBuf, (void __user *)arg, sizeof(*ioBuf)))
        {
            status = -1;
        }
        else
        {
            ioBuf->bufLen = 64 * sizeof(struct spdCompat);
            ipsadm_dumpSPD_compat(ioBuf);
            if (0 != copy_to_user((void __user *) ((ExtIpSecDump_t *)arg)->pBuf,
                                  ioBuf->pBuf, ioBuf->bufLen) ||
                0 != copy_to_user((void __user *)arg, ioBuf, sizeof(*ioBuf)))
            {
                status = -1;
            }
        }
#endif
        break;
    }
    case IOC_REGISTER_IKE_EVENTQ:
    {
        ExtIkeEventQIoctl_t evtq;
        if (0 != copy_from_user(&evtq, (void __user *)arg, sizeof(evtq)))
        {
            status = -1;
        }
        else
        {
            status = ipsadm_registerIkeQueue(&evtq);
            if (0 != copy_to_user((void __user *)arg, &evtq, sizeof(evtq)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
    case IOC_GET_IFMAP:
    {
        if (0 != copy_from_user(&m_ifmap_kern, (void __user *)arg, sizeof(ifmap_entry)))
        {
            status = -1;
            printk("status = -1\n");
        }
        else
        {
            status = validate_ifmap(&m_ifmap_kern, status);
            /* if "internal status" fails */
            if (0 != copy_to_user((void __user*)arg, &m_ifmap_kern, sizeof(ifmap_entry)))
            {
                if (0 <= status) status = -1;
            }
        }
        break;
    }
#endif
    default:
        ERROR_PRINT(("Unsupported IOCTL code: %d", cmd));
        status = -1;
        break;


    }
    return status;
}
#endif
#endif

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MISSIU__
extern int
ipsec_ioctl(unsigned int cmd, unsigned long arg)
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36))
extern long
ipsec_ioctl(struct file *file,
#else
extern int
ipsec_ioctl(struct inode * inode, struct file * file,
#endif
            unsigned int cmd, unsigned long arg)
#endif
{
    int value, status = 0;

#ifdef __KERNEL__
    if (0 != copy_from_user(&value, (void __user *)arg, sizeof(value)))
    {
        status = -1;
        return status;
    }
#else
    value = *(int *)arg;
#endif
    DBUG_PRINT(DEBUG_IPSEC, ("cmd = 0x%x, value = 0x%08x", cmd, value));

    switch (cmd)
    {
    case IOC_DUMP_STATS:
        ips_dumpStats(value);
        DBUG_PRINT(DEBUG_IPSEC, ("Sizeof ipsecConf = %d", sizeof(struct ipsecConf)));
        break;

#ifdef __KERNEL__
    /* TODO: implement modStats for missiu */
    case IOC_ENABLE:
        modStats.active = value;
        break;

    case IOC_TRACE:
        modStats.trace = value;
        ips_dumpStats(0);
        break;

    case IOC_SET_RUNFLAGS:
        modStats.runFlags = value;
        ips_dumpStats(0);
        break;
#endif

    case IOC_ADD_KEY:
    {
#ifdef __KERNEL__
        ExtIpSecKey_t key;
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
        }
        else
        {
            status = ipsadm_addKey(&key);
            if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
        status = ipsadm_addKey((ExtIpSecKey_t *)arg);
#endif
        break;
    }
    case IOC_ADD_KEY_EX:
    {
#ifdef __KERNEL__
        ExtIpSecKeyEx_t key;
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
        }
        else
        {
            status = ipsadm_addKeyEx(&key);
            if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
        status = ipsadm_addKeyEx((ExtIpSecKeyEx_t *)arg);
#endif
        break;
    }
    case IOC_KEY_READY:
    {
#ifdef __KERNEL__
#ifdef __ENABLE_DIGICERT_IPV6__
        ExtIpSecKeyEx_t key;
#else
        struct ipsecKeyEx key;
#endif
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
        }
        else
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            status = ipsadm_readyKey(&key);
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            status = gM_IPSEC_keyReady_ptr(&key);
#else
            status = IPSEC_keyReady(&key);
#endif
#endif
            if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
#ifdef __ENABLE_DIGICERT_IPV6__
        status = ipsadm_readyKey((ExtIpSecKeyEx_t *)arg);
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyReady_ptr((struct ipsecKeyEx *)arg);
#else
        status = IPSEC_keyReady((struct ipsecKeyEx *)arg);
#endif
#endif
#endif
        break;
    }
    case IOC_DEL_KEY:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        IPSECKEY keyData;
#endif
        ubyte4 dwSpi;
#ifdef __KERNEL__
#ifdef __ENABLE_DIGICERT_IPV6__
        ExtIpSecKey_t key;
        ExtIpSecKey_t *keyInfo = &key;
#else
        struct ipsecKey key;
#endif
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
            break;
        }
#endif
#ifdef __ENABLE_DIGICERT_IPV6__
#ifndef __KERNEL__
        ExtIpSecKey_t *keyInfo = (ExtIpSecKey_t *)arg;
#endif
        keyData = &keyInfo->key;
        dwSpi = keyData->dwSpi;

        if (IPSEC_SA_FLAG_IP6 & keyData->flags)
        {
            if (keyData->dwDestAddr)
                keyData->dwDestAddr = (CAST_MOC_IPADDR) keyInfo->dstAddr;
            if (keyData->dwSrcAddr)
                keyData->dwSrcAddr = (CAST_MOC_IPADDR) keyInfo->srcAddr;
        }
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyDelete_ptr(keyData);
#else
        status = IPSEC_keyDelete(keyData);
#endif
#else // !IPV6
#ifdef __KERNEL__
        dwSpi = key.dwSpi;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyDelete_ptr(&key);
#else
        status = IPSEC_keyDelete(&key);
#endif
#else
        dwSpi = ((struct ipsecKey *)arg)->dwSpi;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyDelete_ptr((struct ipsecKey *)arg);
#else
        status = IPSEC_keyDelete((struct ipsecKey *)arg);
#endif
#endif
#endif
        /*DUMP_LONGS((ubyte *)keyData, sizeof(*keyData), 80, "Key Delete Info");*/

#ifdef __KERNEL__
        if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
        {
            if (0 <= status) status = -1;
        }
#endif
        if (OK > status)
        {
            ERROR_PRINT(("Error deleting key (spi=%x): status=%d", dwSpi, status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Key (spi=%x) deleted", dwSpi));
        break;
    }
    case IOC_KEY_INIT:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        IPSECKEY keyData;
#endif
#ifdef __KERNEL__
#ifdef __ENABLE_DIGICERT_IPV6__
        ExtIpSecKey_t key;
        ExtIpSecKey_t *keyInfo = &key;
#else
        struct ipsecKey key;
#endif
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
            break;
        }
#endif
#ifndef __ENABLE_DIGICERT_IPV6__
#ifdef __KERNEL__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyInitiate_ptr(&key);
#else
        status = IPSEC_keyInitiate(&key);
#endif
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyInitiate_ptr((struct ipsecKey *)arg);
#else
        status = IPSEC_keyInitiate((struct ipsecKey *)arg);
#endif
#endif
#else
#ifndef __KERNEL__
        ExtIpSecKey_t *keyInfo = (ExtIpSecKey_t *)arg;
#endif
        keyData = &keyInfo->key;

        if (IPSEC_SA_FLAG_IP6 & keyData->flags)
        {
            if (keyData->dwDestAddr)
                keyData->dwDestAddr = (CAST_MOC_IPADDR) keyInfo->dstAddr;
            if (keyData->dwSrcAddr)
                keyData->dwSrcAddr = (CAST_MOC_IPADDR) keyInfo->srcAddr;
        }

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_keyInitiate_ptr(keyData);
#else
        status = IPSEC_keyInitiate(keyData);
#endif
#endif
#ifdef __KERNEL__
        if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
        {
            if (0 <= status) status = -1;
        }
#endif
        break;
    }
#ifdef __ENABLE_MOBIKE__
    case IOC_KEY_UPDATE:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        IPSECKEY keyData;
#endif
#ifdef __KERNEL__
#ifdef __ENABLE_DIGICERT_IPV6__
        ExtIpSecKey_t key;
        ExtIpSecKey_t *keyInfo = &key;
#else
        struct ipsecKey key;
#endif
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
            break;
        }
#endif
#ifndef __ENABLE_DIGICERT_IPV6__
#ifdef __KERNEL__
        status = IPSEC_keyUpdate(&key);
#else
        status = IPSEC_keyUpdate((struct ipsecKey *)arg);
#endif
#else
#ifndef __KERNEL__
        ExtIpSecKey_t *keyInfo = (ExtIpSecKey_t *)arg;
#endif
        keyData = &keyInfo->key;

        if (IPSEC_SA_FLAG_IP6 & keyData->flags)
        {
            if (keyData->dwDestAddr)
                keyData->dwDestAddr = (CAST_MOC_IPADDR) keyInfo->dstAddr;
            if (keyData->dwSrcAddr)
                keyData->dwSrcAddr = (CAST_MOC_IPADDR) keyInfo->srcAddr;
        }

        status = IPSEC_keyUpdate(keyData);
#endif
#ifdef __KERNEL__
        if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
        {
            if (0 <= status) status = -1;
        }
#endif
        break;
    }
#endif
    case IOC_GET_KEY:
    {
#ifdef __KERNEL__
        ExtIpSecKey_t key;
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
        }
        else
        {
            status = ipsadm_getKey(&key);
            if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
        status = ipsadm_getKey((ExtIpSecKey_t *)arg);
#endif
        break;
    }
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    case IOC_GET_KEY_EX:
    {
#ifdef __KERNEL__
        ExtIpSecKeyEx_t key;
        if (0 != copy_from_user(&key, (void __user *)arg, sizeof(key)))
        {
            status = -1;
        }
        else
        {
            status = ipsadm_getKeyEx(&key);
            if (0 != copy_to_user((void __user *)arg, &key, sizeof(key)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
        status = ipsadm_getKeyEx((ExtIpSecKeyEx_t *)arg);
#endif
        break;
    }
#endif
    case IOC_FLUSH_SA:

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        if (OK > (status = gM_IPSEC_keyFlush_ptr()))
#else
        if (OK > (status = IPSEC_keyFlush()))
#endif
        {
            ERROR_PRINT(("Error flushing key: status=%d", status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Keys flushed"));
        break;

    case IOC_DUMP_SA:
    {
#if !defined(LOADCONFIG_DUMP_TO_STDOUT)
        ipsadm_dumpSA(value);
#else
#ifdef __KERNEL__
        static ubyte sadbBuf[sizeof(ExtIpSecDump_t) +
                             (IPSEC_SADB_MAX * sizeof(struct sadb))] = { 0 };
        ExtIpSecDump_t *ioBuf = (ExtIpSecDump_t *)sadbBuf;
        if (0 != copy_from_user(ioBuf, (void __user *)arg, sizeof(*ioBuf)))
        {
            status = -1;
        }
        else
        {
            ubyte4 bufLen = ioBuf->bufLen;
            ipsadm_dumpSA(ioBuf);
            if (0 != copy_to_user((void __user *) ((ExtIpSecDump_t *)arg)->pBuf,
                                  ioBuf->pBuf, bufLen) ||
                0 != copy_to_user((void __user *)arg, ioBuf, sizeof(*ioBuf)))
            {
                status = -1;
            }
        }
#else
        ipsadm_dumpSA((ExtIpSecDump_t *)arg);
#endif
#endif
        break;
    }
    case IOC_GET_SADB_SIZE:
    {
#ifdef __KERNEL__
        int size = sizeof(struct sadb);
        if (0 != copy_to_user((void __user *)arg, &size, sizeof(size)))
        {
            status = -1;
        }
#else
        *(int *)arg = sizeof(struct sadb);
#endif
        break;
    }
    case IOC_ADD_CONF:
    {
#ifdef __KERNEL__
        ExtIpSecConf_t conf;
        if (0 != copy_from_user(&conf, (void __user *)arg, sizeof(conf)))
        {
            status = -1;
        }
        else
        {
            status = ipsadm_addConf(&conf);
            if (0 != copy_to_user((void __user *)arg, &conf, sizeof(conf)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
        status = ipsadm_addConf((ExtIpSecConf_t *)arg);
#endif
        break;
    }
    case IOC_DEL_CONF:
    {
#ifdef __KERNEL__
        struct ipsecConf conf;
        if (0 != copy_from_user(&conf, (void __user *)arg, sizeof(conf)))
        {
            status = -1;
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            status = gM_IPSEC_confDelete_ptr(&conf);
#else
            status = IPSEC_confDelete(&conf);
#endif
            if (0 != copy_to_user((void __user *)arg, &conf, sizeof(conf)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_confDelete_ptr((IPSECCONF)arg);
#else
        status = IPSEC_confDelete((IPSECCONF)arg);
#endif
#endif
        if (OK > status)
        {
            ERROR_PRINT(("Error deleting policy: status=%d", status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Policy deleted"));
        break;
    }
    case IOC_FLUSH_SPD:

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        if (OK > (status = gM_IPSEC_confFlush_ptr()))
#else
        if (OK > (status = IPSEC_confFlush()))
#endif
        {
            ERROR_PRINT(("Error flushing configs: status=%d", status));
            break;
        }
        DBUG_PRINT(DEBUG_IPSEC, ("Config flushed"));
        break;

    case IOC_DUMP_SPD:
    {
#if !defined(LOADCONFIG_DUMP_TO_STDOUT)
        ipsadm_dumpSPD(value);
#else
#ifdef __KERNEL__
        static ubyte spdBuf[sizeof(ExtIpSecDump_t) +
                            (IPSEC_SPD_MAX * 2 * sizeof(struct spd))] = { 0 };
        ExtIpSecDump_t *ioBuf = (ExtIpSecDump_t *)spdBuf;;
        if (0 != copy_from_user(ioBuf, (void __user *)arg, sizeof(*ioBuf)))
        {
            status = -1;
        }
        else
        {
            ubyte4 bufLen = ioBuf->bufLen;
            ipsadm_dumpSPD(ioBuf);
            if (0 != copy_to_user((void __user *) ((ExtIpSecDump_t *)arg)->pBuf,
                                  ioBuf->pBuf, bufLen) ||
                0 != copy_to_user((void __user *)arg, ioBuf, sizeof(*ioBuf)))
            {
                status = -1;
            }
        }
#else
        ipsadm_dumpSPD((ExtIpSecDump_t *)arg);
#endif
#endif
        break;
    }
    case IOC_REGISTER_IKE_EVENTQ:
    {
#ifdef __KERNEL__
        ExtIkeEventQIoctl_t evtq;
        if (0 != copy_from_user(&evtq, (void __user *)arg, sizeof(evtq)))
        {
            status = -1;
        }
        else
        {
            status = ipsadm_registerIkeQueue(&evtq);
            if (0 != copy_to_user((void __user *)arg, &evtq, sizeof(evtq)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
        status = ipsadm_registerIkeQueue((ExtIkeEventQ_t *)arg);
#endif
        break;
    }
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
    case IOC_GET_IFMAP:
    {
#ifdef __KERNEL__
        if (0 != copy_from_user(&m_ifmap_kern, (void __user *)arg, sizeof(ifmap_entry)))
        {
            status = -1;
            printk("status = -1\n");
        }
        else
        {
            status = validate_ifmap(&m_ifmap_kern, status);
            /* if "internal status" fails */
            if (0 != copy_to_user((void __user*)arg, &m_ifmap_kern, sizeof(ifmap_entry)))
            {
                if (0 <= status) status = -1;
            }
        }
#else
        status = validate_ifmap(&m_ifmap_kern, 1);
#endif
        break;
    }
#endif
    default:
        ERROR_PRINT(("Unsupported IOCTL code: %d", cmd));
        status = -1;
        break;
    }

    return status;
}


/*
 * IPsec to IKE bridge
 */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IKE_SERVER__

#ifdef __KERNEL__
static sbyte4
IKE_evtSend(ubyte *pBuffer, ubyte4 dwBufferSize,
            MOC_IP_ADDRESS dwHostAddr,
            ubyte4 cookie)
{
    MSTATUS            status  = OK;
    ExtIkeEventQ_t     *iqueue = &modStats.ikeQueue;
    struct task_struct *task;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
    static DEFINE_SPINLOCK(mr_lock);
#else
    static spinlock_t mr_lock = SPIN_LOCK_UNLOCKED;
#endif
    spin_lock_bh(&mr_lock);

    if (0 == iqueue->tid)
    {
        status = ERR_IKE;
        goto exit;
    }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
    task = find_task_by_pid(iqueue->tid);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
    task = find_task_by_pid_ns(iqueue->tid, &init_pid_ns);
#else
    /* find_task_by_pid_ns() is no longer EXPORTED */
    rcu_read_lock();
    task = pid_task(find_pid_ns(iqueue->tid, &init_pid_ns), PIDTYPE_PID);
    rcu_read_unlock();
#endif
    if (0 == task)
    {
        ERROR_PRINT(("IKE process not found.  pid: %d", iqueue->tid));
        status = ERR_IKE;
        iqueue->tid = 0;
        goto exit;
    }

    DUMP_LONGS(pBuffer, sizeof(struct ike_event), 80, "Event to IKE");
    if (0 > (status =
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_queue_put_tail_ptr(iqueue->msgQueue, pBuffer, sizeof(struct ike_event))))
#else
        queue_put_tail(iqueue->msgQueue, pBuffer, sizeof(struct ike_event))))
#endif
    {
        goto exit;
    }

    modStats.output.ikeMsgs++;
    status = send_sig(iqueue->signal, task, 1);

    MOC_UNUSED(dwBufferSize);
    MOC_UNUSED(dwHostAddr);
    MOC_UNUSED(cookie);

exit:
    spin_unlock_bh(&mr_lock);
    return (sbyte4)status;
}
#else
/* missiu */
static sbyte4
IKE_evtSend(ubyte *pBuffer, ubyte4 dwBufferSize,
            MOC_IP_ADDRESS dwHostAddr,
            ubyte4 cookie)
{
    sbyte4 status;
    mqd_t mqdes = -1;

    if (0 == extQueue.name[0])
    {
        ERROR_PRINT(("No IKE queue registered."));
        return ERR_IKE;
    }
    mqdes = mq_open(extQueue.name, O_WRONLY|O_NONBLOCK);
    if (-1 == mqdes)
    {
        ERROR_PRINT(("Failed to open IKE queue %s: %s", extQueue.name,
                     strerror(errno)));
        return -1;
    }
    status = mq_send(mqdes, pBuffer, sizeof(struct ike_event), 0);
    if (-1 == status)
    {
        ERROR_PRINT(("Failed to send event to IKE: %s", strerror(errno)));
        mq_close(mqdes);
        return ERR_IKE;
    }
    DBUG_PRINT(DEBUG_IPSEC, ("Sent event to IKE"));
    mq_close(mqdes);
    return status;
}
#endif


/*------------------------------------------------------------------*/

static ikeSettings m_ikeSettings = { 0 };

extern sbyte4
IKE_setIkeSettings(sbyte4 (*setIkeSettings)(void *))
{
    m_ikeSettings.funcPtrIkeEvtSend = IKE_evtSend;
#ifdef __ENABLE_IPSEC_NAT_T__
/*    m_ikeSettings.funcPtrIkeNattSend = IKE_nattSend;*/
#endif
    if (NULL == setIkeSettings) return ERR_NULL_POINTER;

    setIkeSettings((void *) &m_ikeSettings);
    return OK;
}

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

