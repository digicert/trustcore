/*
 * moc_ipsec_main.c
 *
 * IPsec kernel module main entry point
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include "../common/mtypes.h"
#include "../common/initmocana.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/mem_pool.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../harness/harness.h"
#include "../platform/kmem_part.h"

#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipsec_crypto.h"
#include "../ipsec/sadb.h"
#include "../ipsec/spd.h"

MODULE_AUTHOR("www.digicert.com");
MODULE_LICENSE("DIGICERT INC");
MODULE_DESCRIPTION("DigiCert IPsec module");

#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
extern intBoolean m_ipsecSadbForever;
#endif
extern moctime_t gStartTime;

extern ubyte4 LINUX_deltaMS(const moctime_t* origin, moctime_t* curtime);

typedef void (*UNLOAD_CALLBACK_HANDLER)(void);
UNLOAD_CALLBACK_HANDLER unload_callback = NULL;

void register_unload_callback(UNLOAD_CALLBACK_HANDLER cb)
{
    unload_callback = cb;
}

static int __init ipsec_init(void)
{
    printk(KERN_INFO "Load IPSec module\n");
    return 0;
}

static void __exit ipsec_cleanup(void)
{
    unsigned long j1;

    printk(KERN_INFO "Preparing moc_ipsec cleaning ....\n");

    // If unload callback is registered, make it now and wait for continue
    if (unload_callback)
    {
        // Inform registered driver about unload on this driver
        unload_callback();

        j1 = jiffies + (1 * HZ);
        while (time_before(jiffies, j1))
            schedule();
    }
    printk(KERN_INFO "Cleaned up moc_ipsec module.\n");
}

/*************************************************************
 *    SYMBOLS to be EXPORTED
 *************************************************************/
EXPORT_SYMBOL(IPSEC_applyEx);
EXPORT_SYMBOL(IPSEC_checkSp);
EXPORT_SYMBOL(IPSEC_cipherSuite);
EXPORT_SYMBOL(IPSEC_confAdd);
EXPORT_SYMBOL(IPSEC_confAdd1);
EXPORT_SYMBOL(IPSEC_confDelete);
EXPORT_SYMBOL(IPSEC_confFlush);
EXPORT_SYMBOL(IPSEC_cryptoInit);
EXPORT_SYMBOL(IPSEC_cryptoUninit);
EXPORT_SYMBOL(IPSEC_delSa);
EXPORT_SYMBOL(IPSEC_delSp);
EXPORT_SYMBOL(IPSEC_enumSa);
EXPORT_SYMBOL(IPSEC_enumSp);
EXPORT_SYMBOL(IPSEC_expireSa);
EXPORT_SYMBOL(IPSEC_findSa);
EXPORT_SYMBOL(IPSEC_flush);
EXPORT_SYMBOL(IPSEC_flushSadb);
EXPORT_SYMBOL(IPSEC_flushSpd);
EXPORT_SYMBOL(IPSEC_getCipherSuite);
EXPORT_SYMBOL(IPSEC_getHmacSuite);
EXPORT_SYMBOL(IPSEC_getMaxCipherSuites);
EXPORT_SYMBOL(IPSEC_getMaxHmacSuites);
EXPORT_SYMBOL(IPSEC_getSa);
EXPORT_SYMBOL(IPSEC_getSp);
EXPORT_SYMBOL(IPSEC_getSp2);
EXPORT_SYMBOL(IPSEC_getSpd);
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
EXPORT_SYMBOL(IPSEC_groupKeyAdd);
#endif
EXPORT_SYMBOL(IPSEC_hmacSuite);
EXPORT_SYMBOL(IPSEC_indexSp);
EXPORT_SYMBOL(IPSEC_init);
EXPORT_SYMBOL(IPSEC_initSadb);
EXPORT_SYMBOL(IPSEC_initSpd);
EXPORT_SYMBOL(IPSEC_keyAdd);
EXPORT_SYMBOL(IPSEC_keyAddEx);
EXPORT_SYMBOL(IPSEC_keyDelete);
EXPORT_SYMBOL(IPSEC_keyFlush);
EXPORT_SYMBOL(IPSEC_keyGet);
EXPORT_SYMBOL(IPSEC_keyGetEx);
EXPORT_SYMBOL(IPSEC_keyInitiate);
EXPORT_SYMBOL(IPSEC_keyReady);
EXPORT_SYMBOL(IPSEC_keyUpdate);
EXPORT_SYMBOL(IPSEC_matchSp);
EXPORT_SYMBOL(IPSEC_newSa);
EXPORT_SYMBOL(IPSEC_newSp);
EXPORT_SYMBOL(IPSEC_permitEx);
EXPORT_SYMBOL(IPSEC_ready);
EXPORT_SYMBOL(IPSEC_setIkeSettings);
EXPORT_SYMBOL(SetUdpChecksum);
EXPORT_SYMBOL(SetTcpChecksum);
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
EXPORT_SYMBOL(DEBUG_CONSOLE_dump_data);
EXPORT_SYMBOL(DEBUG_CONSOLE_printf);
EXPORT_SYMBOL(m_errorClass);
#endif

EXPORT_SYMBOL(DIGI_HTONS);
EXPORT_SYMBOL(DIGI_NTOHS);
EXPORT_SYMBOL(DIGI_MEMCPY);
EXPORT_SYMBOL(DIGI_MEMSET);
EXPORT_SYMBOL(DIGICERT_initialize);
EXPORT_SYMBOL(DIGICERT_freeDigicert);
EXPORT_SYMBOL(queue_put_tail);
EXPORT_SYMBOL(gStartTime);
#ifdef __ENABLE_DIGICERT_INFINTE_KEY_TIMEOUT__
EXPORT_SYMBOL(m_ipsecSadbForever);
#endif

#ifdef __ENABLE_DIGICERT_IPV6__
EXPORT_SYMBOL(SetUdp6Checksum);
EXPORT_SYMBOL(SetTcp6Checksum);
EXPORT_SYMBOL(CmpIpAddr6);
#endif

module_init(ipsec_init);
module_exit(ipsec_cleanup);
