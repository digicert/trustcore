/*
 * nf_ipsec.c
 *
 * Linux IPsec kernel module
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

#include "moptions.h"

#include <linux/types.h>
#include <linux/ip.h>

#ifndef CONFIG_NETFILTER
  #define CONFIG_NETFILTER
  #define _NF_CONFIG_FOR_BUILD_
#endif
#include <linux/netfilter.h>
#ifdef _NF_CONFIG_FOR_BUILD_
  #undef CONFIG_NETFILTER
#endif

#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <net/checksum.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/udp.h>
#ifdef __ENABLE_DIGICERT_IPV6__
#include <net/ipv6.h>
#include <net/protocol.h>
#endif
#include <net/tcp.h>
#include <net/route.h>
#include <asm/io.h>
#include <asm/checksum.h>
#include <asm/atomic.h>

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
#include <linux/init.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#endif

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

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_frag.h"
#include "../ipsec/ipsec_crypto.h"
#ifdef __ENABLE_IPSEC_FLOW__
#include "../ipsec/ipsec_flow.h"
#endif
#include "../ipsec/sadb.h"
#include "../ipsec/spd.h"

#ifdef __ENABLE_DIGICERT_IPV6__
#include "../ipsec/ipsec_protos.h"
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
#define SET_MOC_IPADDR6_GPL(s, v)   (s).family = AF_INET6; (s).uin.addr6[4] = 0;\
                                 gM_DIGI_MEMCPY_ptr((ubyte *) (s).uin.addr6, (const ubyte *)(v), 16)
#else
#define SET_MOC_IPADDR6_GPL(s, v)   (s).family = AF_INET6; (s).uin.addr6[4] = 0;\
                                 DIGI_MEMCPY((ubyte *) (s).uin.addr6, (const ubyte *)(v), 16)
#endif

#endif

#include "nf_ipsec.h"
#include "nf_ipsec_priv.h"
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
#include "../examples/if_mapping.h"
#endif

MODULE_LICENSE("GPL");

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)

typedef sbyte4 (*IPSEC_setIkeSettings_funcptr)(void *);
IPSEC_setIkeSettings_funcptr gM_IPSEC_setIkeSettings_ptr = NULL;

typedef MSTATUS (* DIGICERT_initialize_funcptr)(InitMocanaSetupInfo *, MocCtx *);
DIGICERT_initialize_funcptr gM_DIGICERT_initialize_ptr = NULL;

IPSEC_keyFlush_funcptr gM_IPSEC_keyFlush_ptr = NULL;
IPSEC_groupKeyAdd_funcptr gM_IPSEC_groupKeyAdd_ptr = NULL;

IPSEC_confAdd1_funcptr gM_IPSEC_confAdd1_ptr = NULL;

IPSEC_enumSa_funcptr gM_IPSEC_enumSa_ptr = NULL;

queue_put_tail_funcptr gM_queue_put_tail_ptr = NULL;

IPSEC_confFlush_funcptr gM_IPSEC_confFlush_ptr = NULL;

DIGI_MEMSET_funcptr gM_DIGI_MEMSET_ptr = NULL;
DIGI_MEMCPY_funcptr gM_DIGI_MEMCPY_ptr = NULL;

IPSEC_keyGet_funcptr gM_IPSEC_keyGet_ptr = NULL;
IPSEC_keyGetEx_funcptr gM_IPSEC_keyGetEx_ptr = NULL;
IPSEC_keyDelete_funcptr gM_IPSEC_keyDelete_ptr = NULL;

typedef sbyte4 (* DIGICERT_freeDigicert_funcptr)(void);
DIGICERT_freeDigicert_funcptr gM_DIGICERT_freeDigicert_ptr = NULL;

typedef sbyte4 (*IPSEC_flush_funcptr)(void);
IPSEC_flush_funcptr gM_IPSEC_flush_ptr = NULL;

typedef sbyte4 (*IPSEC_applyEx_funcptr)(ubyte *, ubyte2, ubyte2*, ubyte2*,
                                        struct ipsecCtx *);
IPSEC_applyEx_funcptr gM_IPSEC_applyEx_ptr = NULL;

typedef void (*SetTcpChecksum_funcptr)(ubyte *, ubyte4, ubyte4, ubyte2);
SetTcpChecksum_funcptr gM_SetTcpChecksum_ptr = NULL;

typedef void (*SetUdpChecksum_funcptr)(ubyte *, ubyte4, ubyte4);
SetUdpChecksum_funcptr gM_SetUdpChecksum_ptr = NULL;

typedef sbyte4 (*IPSEC_permitEx_funcptr)(ubyte *, ubyte2,
                                 ubyte2 *, ubyte2 *,
                                 struct ipsecCtx *);
IPSEC_permitEx_funcptr gM_IPSEC_permitEx_ptr = NULL;

IPSEC_keyAdd_funcptr gM_IPSEC_keyAdd_ptr = NULL;
IPSEC_keyAddEx_funcptr gM_IPSEC_keyAddEx_ptr = NULL;

IPSEC_keyInitiate_funcptr gM_IPSEC_keyInitiate_ptr = NULL;

typedef sbyte4 (*IPSEC_ready_funcptr)(MOC_IP_ADDRESS,
                              MOC_IP_ADDRESS,
                              ubyte,
                              intBoolean, intBoolean,
                              ubyte2, ubyte2,
                              intBoolean, struct spd **,
                              sbyte4, ubyte4);
IPSEC_ready_funcptr gM_IPSEC_ready_ptr = NULL;

typedef sbyte4 (*IPSEC_init_funcptr)(void);
IPSEC_init_funcptr gM_IPSEC_init_ptr = NULL;

typedef void (*UNLOAD_CALLBACK_HANDLER)(void);
typedef void (*REGISTER_UNLOAD_CALLBACK_HANDLER)(UNLOAD_CALLBACK_HANDLER);
REGISTER_UNLOAD_CALLBACK_HANDLER gM_register_unload_callback_ptr = NULL;

#ifdef __ENABLE_DIGICERT_IPV6__
SetUdp6Checksum_funcptr gM_SetUdp6Checksum_ptr = NULL;
SetTcp6Checksum_funcptr gM_SetTcp6Checksum_ptr = NULL;
CmpIpAddr6_funcptr gM_CmpIpAddr6_ptr = NULL;

#define SAME_MOC_IPADDR_GPL(a, s)   (((a) == &(s)) ||\
                                 ((a) && ((a)->family == (s).family) &&\
                                  (((AF_INET == (a)->family) &&\
                                    ((a)->uin.addr == (s).uin.addr))\
                                   ||\
                                   ((AF_INET6 == (a)->family) &&\
                                    (0 == gM_CmpIpAddr6_ptr((ubyte *) (a)->uin.addr6, (ubyte *) (s).uin.addr6))))))
#endif
static int resolve_external_symbols(void);
#else
#define SAME_MOC_IPADDR_GPL         SAME_MOC_IPADDR
#endif


static volatile ubyte module_unloaded = 0;

/*------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17))
  #define SKB_LINEARIZE(a)          skb_linearize((a), GFP_ATOMIC)
  #define NF_REGISTER_HOOKS(o, s)   ((0 > (s = nf_register_hook(o))) ? s : \
                                     ((0 > (s = nf_register_hook(o + 1))) ? s : \
                                            (s = nf_register_hook(o + 2))))
  #define NF_UNREGISTER_HOOKS(o)    nf_unregister_hook(o + 2); \
                                    nf_unregister_hook(o + 1); \
                                    nf_unregister_hook(o)
#else
  #define SKB_LINEARIZE(a)          skb_linearize((a))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0))
  #define NF_REGISTER_HOOKS(o, s)   (s = nf_register_hooks(o, ARRAY_SIZE(o)))
  #define NF_UNREGISTER_HOOKS(o)    nf_unregister_hooks(o, ARRAY_SIZE(o))
#else
  #define NF_REGISTER_HOOKS(o, s)   (s = nf_register_net_hooks(&init_net, o, ARRAY_SIZE(o)))
  #define NF_UNREGISTER_HOOKS(o)    nf_unregister_net_hooks(&init_net, o, ARRAY_SIZE(o))
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
  #define NF_HOOK_LOCAL_OUT         NF_IP_LOCAL_OUT
  #define NF_HOOK_LOCAL_IN          NF_IP_LOCAL_IN
  #define NF_HOOK_FORWARD           NF_IP_FORWARD
  #define NF_HOOK_PRE_ROUTE         NF_IP_PRE_ROUTING
  #define NF_HOOK_POST_ROUTE        NF_IP_POST_ROUTING
#else
  #define NF_HOOK_LOCAL_OUT         NF_INET_LOCAL_OUT
  #define NF_HOOK_LOCAL_IN          NF_INET_LOCAL_IN
  #define NF_HOOK_FORWARD           NF_INET_FORWARD
  #define NF_HOOK_PRE_ROUTE         NF_INET_PRE_ROUTING
  #define NF_HOOK_POST_ROUTE        NF_INET_POST_ROUTING
#endif


/*------------------------------------------------------------------*/

#if 0 /* for reference only */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
typedef unsigned int nf_hookfn(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state)

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
typedef unsigned int nf_hookfn(const struct nf_hook_ops *ops,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state);

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
typedef unsigned int nf_hookfn(const struct nf_hook_ops *ops,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *));

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
typedef unsigned int nf_hookfn(unsigned int hooknum,
                               struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *));

#else
typedef unsigned int nf_hookfn(unsigned int hooknum,
                               struct sk_buff **pskb,
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *));
#endif
#endif /* 0 */


/*------------------------------------------------------------------*/

#define IPSC_NAME  "moc_ipsec"          /* Device name for ipsec mod */

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
static int mIPsecDevMajor;
static struct class *mIPsecDevClass;
#else
#define IPSC_MAJOR (103)                /* Device major # */
#endif

#define NF_IP_PRI_IPSEC (1)             /* Netfilter IP priority */

/*#define CHECK_MOD_STATS */

ModStats_t modStats =
{
    .active   = 1,
    .runFlags = 0,
};

extern int PFKEY_init(void);
extern void PFKEY_cleanup(void);

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
static ubyte2 m_mtu;
#define IPV4_HEADER_SIZE 20
ifmap_entry m_ifmap_kern = {0};

/*------------------------------------------------------------------*/
static int
ipsec_modify_ip(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                struct sk_buff **pskb,
#else
                struct sk_buff *skb, /* skb_copy handed in */
#endif
                int map_id,
                intBoolean isInbound)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#endif
    int status = 0, len, df;

    struct iphdr *iphdr;

#ifdef __ENABLE_DIGICERT_IPV6__
    struct ipv6hdr *ipv6hdr;
    int offset;
#endif

    u8 protocol;
#ifdef __ENABLE_DIGICERT_IPV6__
        if (m_ifmap_kern.af == AF_INET6)
        {
            offset = ipv6_get_ulp(skb, &protocol, NULL);
            if (offset == -1)
            {
                ERROR_PRINT(("Failed to find ipv6 transport header (out)", 0));
                status = -1;
                goto exit;
            }

            if (IPPROTO_UDP == ip6hdr->protocol)
            {
                struct ipv6hdr ip6hdr = ipv6_hdr(skb);
                /* set pkt_type */
                if (isInbound)
                    skb->pkt_type = PACKET_HOST;
                else
                    skb->pkt_type = PACKET_OUTGOING;

                /* ipv6 has no csum  - for ipv6, the udp csum is mandatory,
                 * which we do after in ipsec_apply_psk */
                ip6hdr->daddr = m_ifmap_kern.element[map_id].multicast_address.v6;

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
                gM_SetUdp6Checksum_ptr(skb->data + offset,
#else
                SetUdp6Checksum(skb->data + offset,
#endif
                                ipv6hdr->saddr.s6_addr, ipv6hdr->daddr.s6_addr);
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
        }
        else
#endif
        {
            iphdr = skb_ip_header(skb);
            protocol = iphdr->protocol;
            if (IPPROTO_UDP == protocol)
            {
                /* set pkt_type */
                if (isInbound)
                    skb->pkt_type = PACKET_HOST;
                else
                    skb->pkt_type = PACKET_OUTGOING;


                /* reset iphdr->daddr */
                if (isInbound)
                {
                    DB_PRINT("ipsec_modify_ip IP header dmac set to broadcast mapping\n");
                    iphdr->daddr = m_ifmap_kern.element[map_id].broadcast_address.v4;
                }
                else
                {
                    DB_PRINT("ipsec_modify_ip IP header dmac set to multicast mapping\n");
                    iphdr->daddr = m_ifmap_kern.element[map_id].multicast_address.v4;
                }

                /* reset ip csum */
                DB_PRINT("ipsec_modify_ip UDP and IP csum reset\n");
                SET_HTONS(iphdr->check, 0);
                SET_IPHDR_CSUM(iphdr->check, iphdr, iphdr->ihl);

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
                gM_SetUdpChecksum_ptr((unsigned char *)iphdr + (iphdr->ihl * 4),
#else
                SetUdpChecksum((unsigned char *)iphdr + (iphdr->ihl * 4),
#endif
                               ntohl(iphdr->saddr), ntohl(iphdr->daddr));
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
        }

#ifdef CHECK_MOD_STATS
    if (modStats.trace)
    {
        DBUG_PRINT(DEBUG_IPSEC,("Status:%d proto:%d\n", status, protocol));
    }
#endif

exit:
    return status;
} /* ipsec_modify_ip */

/*------------------------------------------------------------------*/
static int
ipsec_add_eth(struct spd *pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
                struct sadb *pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                struct sk_buff **pskb,
#else
                struct sk_buff *skb,
#endif
                int local_out,
                int map_id)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#endif
    int status = 0;

    struct iphdr *niphdr;
#ifdef __ENABLE_DIGICERT_IPV6__
    int offset;
#endif

    u8 protocol;
    int ret = 0;

    /* Prepend MAC header. Check that UDP csum was reset in ispec_apply_psk. */
    if (local_out && CHECKSUM_UNNECESSARY == skb->ip_summed)
    {
        struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxSp->dwDestIP.family == AF_INET6)
        {
            offset = ipv6_get_ulp(nskb, &protocol, NULL);
            if (offset == -1)
            {
                ERROR_PRINT(("Failed to find ipv6 transport header (out)", 0));
                status = -1;
                goto exit;
            }

            if (IPPROTO_AH == protocol || IPPROTO_ESP == protocol)
            {
                nskb->dev = dev_get_by_name(&init_net,
                            m_ifmap_kern.element[map_id].if_name);
                nskb->pkt_type = PACKET_OUTGOING;

                /* read in dmac and smac from m_ifmap_kern */
                dev_hard_header(nskb, nskb->dev,
                                ETH_P_IPV6,
                                &htonl(in_aton(m_ifmap_kern.element.[map_id].dmac),
                                &htonl(in_aton(m_ifmap_kern.element.[map_id].smac),
                                nskb->len);

                /* grab ref and transmit */
                dev_hold(nskb->dev);
                int ret = dev_queue_xmit(nskb);
                if (0 != ret)
                    ERROR_PRINT(("Cannot transmit sk_buff", 0));
                dev_put(nskb->dev);
            }
        }
        else
#endif
        {
            niphdr = skb_ip_header(nskb);
            protocol = niphdr->protocol;
            if (IPPROTO_AH == protocol || IPPROTO_ESP == protocol)
            {
                nskb->dev = dev_get_by_name(&init_net,
                m_ifmap_kern.element[map_id].if_name);
                nskb->pkt_type = PACKET_OUTGOING;

                dev_hard_header(nskb, nskb->dev,
                                ETH_P_IP,
                                m_ifmap_kern.element[map_id].dmac,
                                m_ifmap_kern.element[map_id].smac,
                                nskb->len);

                /* grab ref and transmit */
                dev_hold(nskb->dev);
                ret = dev_queue_xmit(nskb);

                if (0 != ret)
                    ERROR_PRINT(("Cannot transmit sk_buff", 0));

                dev_put(nskb->dev);
            }
        }
    }

#ifdef CHECK_MOD_STATS
    if (modStats.trace)
    {
        DBUG_PRINT(DEBUG_IPSEC,("Status:%d proto:%d", status, protocol));
    }
#endif

    return status;
} /* ipsec_add_eth */

/*------------------------------------------------------------------*/
static int
ifmap_kern_get_id(struct iphdr *iphdr, ubyte2 port, intBoolean isInbound)
{
    __be32 ldaddr = 0;
    int map_id = -1;

    /* loop through m_ifmap_kern */
    int i = 0;
    for (i = 0; i < m_ifmap_kern.count; i++)
    {
        if (isInbound)
            ldaddr = (__be32)m_ifmap_kern.element[i].multicast_address.v4;
        else
            /* match niphdr->daddr to m_ifmap_kern->broadcast_address on outbound packet*/
            ldaddr = (__be32)m_ifmap_kern.element[i].broadcast_address.v4;

#ifdef MOCANA_IPSEC_DEBUGGING
        /* For debugging only */
        /*-------------------------------------------*/
        printk("daddr: %u.%u.%u.%u\n", ((unsigned char *)&ldaddr)[0], ((unsigned char *)&ldaddr)[1], ((unsigned char *)&ldaddr)[2], ((unsigned char *)&ldaddr)[3]);
        printk("iphdr->daddr: %u.%u.%u.%u\n", ((unsigned char *)&iphdr->daddr)[0], ((unsigned char *)&iphdr->daddr)[1], ((unsigned char *)&iphdr->daddr)[2], ((unsigned char *)&iphdr->daddr)[3]);
        /*-------------------------------------------*/
#endif
        if(iphdr->daddr == ldaddr)
        {
            /* for loop here if port_mapping_count not 0,1 */
            if (1 < m_ifmap_kern.element[i].port_mapping_count)
            {
                int j = 0;
                for (j = 0; j < m_ifmap_kern.element[i].port_mapping_count; j++)
                {
                    /* found */
                    if (port == m_ifmap_kern.element[i].port_mapping_list[j])
                    {
                        /* right entry found; use this id */
                        map_id = i;
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                        DB_PRINT("\n mapping port: %d  passed port: %d i %d j %d", m_ifmap_kern.element[i].port_mapping_list[j], port, i, j);
#endif
                        break;
                    }
                }
                /* Right entry found, exit from the outer loop as well */
                if (-1 != map_id)
                    break;
            }
            else
            {
                /* in the case of port 0 or only one port. */
                if (!m_ifmap_kern.element[i].port_mapping_list[0] ||
                   (port == m_ifmap_kern.element[i].port_mapping_list[0]))
                {
                    /* right entry found; use this id */
                    map_id = i;
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                    DB_PRINT("\n mapping port: %d  passed port: %d", m_ifmap_kern.element[i].port_mapping_list[0], port);
#endif
                    break;
                }
            }
        }
    }

    /* no correct entry */
    if (i == m_ifmap_kern.count)
    {
        map_id = -1;
    }

    return map_id;
}

/*------------------------------------------------------------------*/
static int
ifmap_kern_get_id6(struct ipv6hdr *ip6hdr, intBoolean isInbound)
{
    int map_id = 0;
    intBoolean isEqual = TRUE;

    /* loop through m_ifmap_kern */
    int i = 0;
    for (i = 0; i < m_ifmap_kern.count; i++)
    {
        if (isInbound)
        {
            int j = 0;
            for (j = 0; j < 16; j++)
            {
                /* match niphdr->daddr to m_ifmap_kern->broadcast_address */
                if(ip6hdr->daddr.s6_addr[j] !=
                       m_ifmap_kern.element[i].broadcast_address.v6[j])
                {
                    /* not equal */
                    isEqual = FALSE;
                    break;
                }
            }

            if (isEqual)
            {
                map_id = i;
                break;
            }
        }
        else
        {
            int k = 0;
            for (k = 0; k < 16; k++)
            {
                /* match niphdr->daddr to m_ifmap_kern->multicast_address */
                if(ip6hdr->daddr.s6_addr[k] !=
                       m_ifmap_kern.element[i].multicast_address.v6[k])
                {
                    /* not equal */
                    isEqual = FALSE;
                    break;
                }
            }

            if (isEqual)
            {
                map_id = i;
                break;
            }
        }
    }

    /* no correct entry */
    if (i == m_ifmap_kern.count)
    {
        map_id = -1;
    }

    return map_id;
}
#endif

/*------------------------------------------------------------------*/
/* Netfilter IP input hook */

static unsigned int
ipsec_in(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
         void *priv,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
         const struct nf_hook_ops *ops,
#else
         unsigned int hooknum,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
         struct sk_buff **pskb,
#else
         struct sk_buff *skb,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
         const struct nf_hook_state *state)
#else
         const struct net_device *in,
         const struct net_device *out,
         int (*okfn) (struct sk_buff *))
#endif
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#endif
#if 0
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    unsigned int hooknum = state->hook;
    const struct net_device *in = state->in;
    const struct net_device *out = state->out;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
    unsigned int hooknum = ops->hooknum;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
    int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    int (*okfn)(struct sock *, struct sk_buff *) = state->okfn;
#endif
#endif /* 0 */
    int           disposition = NF_ACCEPT;
    int           status, len;
    ubyte2        rlen, roff = 0;

    struct ipsecCtx ctx = { 0 };
    struct iphdr *iphdr;

    /* Linearize the buffer */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    if (skb_shared(skb))
    {
        /* printk("\n%s (%d): COPY sk_buff!!!\n", __FUNCTION__, __LINE__); */
        *pskb = skb_copy(skb, GFP_ATOMIC);
        kfree_skb(skb);
        skb = *pskb;
    }
    else
#endif
    if (skb_is_nonlinear(skb) || skb_cloned(skb))
    {
        /* printk("\n%s (%d): LINEARIZE nonlinear=%d clone=%d\n", __FUNCTION__, __LINE__, skb_is_nonlinear(skb), skb_cloned(skb)); */
        if (0 > SKB_LINEARIZE(skb))
        {
            ERROR_PRINT(("Can't linearize packet (in)", 0));
            disposition = NF_DROP;
            goto exit;
        }
    }

    /* Set the IP header */
    iphdr = skb_ip_header(skb);
    if ((NULL == iphdr) || ((ubyte *)iphdr != skb->data))
    {
        ERROR_PRINT(("Bad packet (in)", 0));
        disposition = NF_DROP;
        goto exit;
    }

    len = ntohs(iphdr->tot_len);
    if (len > skb->len)
    {
        ERROR_PRINT(("Bad packet (in)", 0));
        disposition = NF_DROP;
        goto exit;
    }
    skb_trim(skb, len);

#ifdef CHECK_MOD_STATS
    if (len > modStats.input.maxSize)
    {
        modStats.input.maxSize = len;
    }
    if (modStats.trace)
    {
        DUMP_BYTES((ubyte *)iphdr, len, 80, "Input packet");
        DBUG_PRINT(DEBUG_IPSEC,("[proto:%d, sum=%d, len=%d]", iphdr->protocol, skb->ip_summed, len));
    }
    modStats.input.bytes += len;
#endif

    /* Queue input buffer */
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    if ((IPPROTO_AH == iphdr->protocol)
        || (IPPROTO_ESP == iphdr->protocol)
#ifdef __ENABLE_IPSEC_NAT_T__
        || (IPPROTO_UDP == iphdr->protocol)
#endif
        )
    {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
    	DB_PRINT("\n ipsec_in disposition queue");
#endif
        disposition = NF_QUEUE;
        goto exit;
    }
#endif

    /* Process input buffer */

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    status = gM_IPSEC_permitEx_ptr((ubyte *)iphdr, (ubyte2)len,
#else
    status = IPSEC_permitEx((ubyte *)iphdr, (ubyte2)len,
#endif
                            &rlen, &roff, &ctx);
#ifdef MOCANA_IPSEC_DEBUGGING
    if (OK == status)
    {
        printk("IPSEC_permitEx at protocol: %d and status: %d\n",
                iphdr->protocol, status);
        printk("daddr: %u.%u.%u.%u\n", ((unsigned char *)&iphdr->daddr)[0], ((unsigned char *)&iphdr->daddr)[1], ((unsigned char *)&iphdr->daddr)[2], ((unsigned char *)&iphdr->daddr)[3]);
        printk("saddr: %u.%u.%u.%u\n", ((unsigned char *)&iphdr->saddr)[0], ((unsigned char *)&iphdr->saddr)[1], ((unsigned char *)&iphdr->saddr)[2], ((unsigned char *)&iphdr->saddr)[3]);
    }
#endif

    switch (status)
    {
    case OK:
        if (0 != roff)
        {
            skb_pull(skb, roff);
            skb_reset_network_header(skb);
            iphdr = skb_ip_header(skb);
        }
        skb_trim(skb, rlen);
        skb_set_transport_header(skb, (iphdr->ihl * 4));

        if (IPSEC_MODE_TUNNEL == ctx.pxSp->oMode) /* !!! */
        {
            skb_dst_drop(skb);

            if (ip_route_input(skb, iphdr->daddr, iphdr->saddr, iphdr->tos, skb->dev))
            {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
    		DB_PRINT("\n ipsec_in calling dropped here");
#endif
                disposition = NF_DROP;
                break;
            }

            if (RTCF_LOCAL & skb_rtable(skb)->rt_flags)
            {
                /* re-assemble if necessary */
                if (iphdr->frag_off & htons(IP_MF|IP_OFFSET))
                {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                    skb = *pskb = ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER);
                    if (NULL == skb)
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
                    if (0 != (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER)))
#else
                    if (0 != (ip_defrag(&init_net, skb, IP_DEFRAG_LOCAL_DELIVER)))
#endif
                        disposition = NF_STOLEN;
                }
            }
            else /* forwarding */
            {
                /* dst_output() does not involve NF_HOOK_FORWARD. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
                dst_output(skb);
#else
                dst_output(&init_net, skb->sk, skb);
#endif

#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
    		DB_PRINT("\n ipsec_in stolen");
#endif
                disposition = NF_STOLEN;
            }
        }

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
        int map_id = 0;
        struct iphdr *niphdr = skb_ip_header(skb);
        /* print its destination IP address */
        /* print its protocol */
        if (IPPROTO_UDP == niphdr->protocol)
        {
            skb_set_transport_header(skb, IPV4_HEADER_SIZE);
            struct udphdr *pxUdp;
            pxUdp = (struct udphdr*)skb_transport_header(skb);
            ubyte2 pwDstPort;
            if(pxUdp != NULL)
            {
                pwDstPort = GET_NTOHS(pxUdp->dest);
            }
            /* get correct entry */
            map_id = ifmap_kern_get_id(niphdr, pwDstPort, TRUE);
            /* no mapping */
            if(-1 == map_id)
            {
                /* pass through to normal processing */
                goto exit;
            }

#ifdef MOCANA_IPSEC_DEBUGGING
            /* For debugging only */
            __be32 ldaddr = m_ifmap_kern.element[map_id].broadcast_address.v4;

            /*-------------------------------------------*/
            if (OK == status)
            {
                printk("Inspecting ip header for inbound multicast packet. (Note: network byte order)\n");
                printk("daddr: %u.%u.%u.%u\n", ((unsigned char *)&ldaddr)[0], ((unsigned char *)&ldaddr)[1], ((unsigned char *)&ldaddr)[2], ((unsigned char *)&ldaddr)[3]);
                printk("saddr: %u.%u.%u.%u\n", ((unsigned char *)&niphdr->saddr)[0], ((unsigned char *)&niphdr->saddr)[1], ((unsigned char *)&niphdr->saddr)[2], ((unsigned char *)&niphdr->saddr)[3]);
            }
            /*-------------------------------------------*/
#endif

            /* alter ip csum and finish */
            status = ipsec_modify_ip(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                                     pskb,
#else
                                     skb,
#endif
                                     map_id,
                                     TRUE);
            printk("disposition: %d\n", disposition);
        }
#endif
#ifdef CHECK_MOD_STATS
        if (modStats.trace)
        {
            DBUG_PRINT(DEBUG_IPSEC,("Status: %d [proto:%d]", status, iphdr->protocol));
            DBUG_PRINT(DEBUG_IPSEC,("Input decrypted packet #%d", modStats.input.applied+1));
            DUMP_BYTES((ubyte *)iphdr, rlen, 80, "Input decrypted packet");
        }
        modStats.input.applied++;
#endif
        break;

    case STATUS_IPSEC_BYPASS:
        break;

    default:
#ifdef CHECK_MOD_STATS
        modStats.input.errors++;
        modStats.input.lastErr = status;
        DBUG_PRINT(DEBUG_IPSEC,("IPSEC_permit error: status is %d, len=%d", status, len));
#endif

#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
    	DB_PRINT("\n ipsec_in drop 2");
#endif
        disposition = NF_DROP;
        break;
    }

exit:
#ifdef CHECK_MOD_STATS
    modStats.input.all++;
#endif
    if(STATUS_IPSEC_BYPASS != status)
    {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
        DB_PRINT("\n ipsec_in calling permit with disposition=%d", disposition);
#endif
    }
    return disposition;
} /* ipsec_in */


/*************************************************************
 * The following functions are copied from "skbuff.c".
 *************************************************************/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0))
static void skb_drop_fraglist(struct sk_buff *skb)
{
    struct sk_buff *list = skb_shinfo(skb)->frag_list;

    skb_shinfo(skb)->frag_list = NULL;

    do {
        struct sk_buff *this = list;
        list = list->next;
        kfree_skb(this);
    } while (list);
}

static void skb_release_data(struct sk_buff *skb)
{
    if (!skb->cloned ||
        atomic_dec_and_test(&(skb_shinfo(skb)->dataref)))
    {
        if (skb_shinfo(skb)->nr_frags)
        {
            int i;
            for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
                put_page(skb_shinfo(skb)->frags[i].page);
        }

        if (skb_shinfo(skb)->frag_list)
            skb_drop_fraglist(skb);

        kfree(skb->head);
    }
}


/*------------------------------------------------------------------*/

#ifdef CHECK_HEAD_ROOM
static int
ipsec_skb_expand(struct sk_buff *skb)
{
    /* Code based on __skb_linearize() in "dev.c" */
    unsigned int size;
    u8 *data;
    long offset;
    struct skb_shared_info *ninfo;
    int headerlen = skb->data - skb->head;
    int expand = (skb->tail + skb->data_len) - skb->end;

    if (expand <= 0)
        expand = 0;

    size = skb_end_pointer(skb) - skb->head + expand + PAD_XTRA;
    size = SKB_DATA_ALIGN(size);
    data = kmalloc(size + sizeof(struct skb_shared_info), GFP_ATOMIC);
    if (NULL == data)
        return -ENOMEM;

    /* Copy header */
    if (skb_copy_bits(skb, -headerlen, data, headerlen))
        BUG();

    /* Copy data */
    if (skb_copy_bits(skb, 0, data+(headerlen+HEAD_XTRA), skb->len))
        BUG();

    /* Set up shinfo */
    ninfo = (struct skb_shared_info*)(data + size);
    atomic_set(&ninfo->dataref, 1);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
    ninfo->tso_size = skb_shinfo(skb)->tso_size;
    ninfo->tso_segs = skb_shinfo(skb)->tso_segs;
#else
    ninfo->gso_size = skb_shinfo(skb)->gso_size;
    ninfo->gso_segs = skb_shinfo(skb)->gso_segs;
    ninfo->gso_type = skb_shinfo(skb)->gso_type;
#endif
    ninfo->nr_frags = 0;
    ninfo->frag_list = NULL;

    /* Offset between the two in bytes */
    offset = data - skb->head;

    /* Free old data. */
    skb_release_data(skb);

    skb->head = data;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)) || !defined(NET_SKBUFF_DATA_USES_OFFSET)
    skb->end  = data + size;
#else
    skb->end  = size;
#endif

    /* Set up new pointers */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
    skb->h.raw   += offset + HEAD_XTRA;
    skb->nh.raw  += offset + HEAD_XTRA;
    if (NULL != skb->mac.raw)
    skb->mac.raw += offset;
    skb->tail    += offset + HEAD_XTRA;
#else
#ifndef NET_SKBUFF_DATA_USES_OFFSET
    skb->transport_header += offset;
    skb->network_header   += offset;
    if (skb_mac_header_was_set(skb))
    skb->mac_header       += offset;
    skb->tail             += offset;
#endif
    skb->transport_header += HEAD_XTRA;
    skb->network_header   += HEAD_XTRA;
    skb->tail             += HEAD_XTRA;
#endif
    skb->data    += offset + HEAD_XTRA;

    /* We are no longer a clone, even if we were. */
    skb->cloned    = 0;

    skb->tail     += skb->data_len;
    skb->data_len  = 0;
    return 0;
} /* ipsec_skb_expand */
#endif
#endif


/*------------------------------------------------------------------*/

#ifdef CHECK_HEAD_ROOM
static inline void
ipsec_skb_mmac(struct sk_buff *skb)
{
    /* Move skb->mac to acommondate extra headroom for IPsec */
    unsigned char *mac = skb->data - (skb->mac_len + HEAD_XTRA);
    if (mac < skb_mac_header(skb))
    {
#if 0
        printk("\n%s (%d): MOVE mac=@%p[%d] to @%p (hdrm=%d data=@%p[%d] tlrm=%d)\n", __FUNCTION__, __LINE__,
               skb_mac_header(skb), skb->mac_len, mac,
               skb_headroom(skb), skb->data, skb->len, skb_tailroom(skb));
#endif
        if (skb->mac_len)
        {
            memmove(mac, skb_mac_header(skb), skb->mac_len);
        }
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
        skb->mac.raw = mac;
#else
        skb_set_mac_header(skb, -(skb->mac_len + HEAD_XTRA));
#endif
    }
} /* ipsec_skb_mmac */
#endif


/*------------------------------------------------------------------*/

#if !(defined(CHECK_HEAD_ROOM) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)))
static int
ipsec_skb_expand(struct sk_buff *skb)
{
    int status = 0;

    while (skb_is_nonlinear(skb)) /* i.e. skb->data_len != 0 */
    {
        /* e.g. skb_shinfo(skb)->frag_list is set for large ICMP packets.
           Also see the difference between skb->data_len and skb->len */
        if (0 > (status = SKB_LINEARIZE(skb)))
        {
            ERROR_PRINT(("Can't linearize sk_buff for encryption", 0));
            goto exit;
        }
#if 0
        printk("\n%s (%d): LINERIZED hdrm=%d tlrm=%d\n", __FUNCTION__, __LINE__,
               skb_headroom(skb), skb_tailroom(skb));
#endif
#ifdef CHECK_HEAD_ROOM
        if ((skb_tailroom(skb) < TAIL_XTRA) || !SKB_PUSHABLE(skb))
#endif
        if (skb_tailroom(skb) < PAD_XTRA)
            break;

#ifdef CHECK_HEAD_ROOM
        if (SKB_PUSHABLE(skb)) goto mmac;
#endif
        goto exit;
    }

#ifdef CHECK_HEAD_ROOM
    if (0 > (status = pskb_expand_head(skb, HEAD_XTRA, TAIL_XTRA, GFP_ATOMIC)))
    {
        goto exit;
    }

mmac:
    if (skb_mac_header_was_set(skb))
    {
        ipsec_skb_mmac(skb); /* move 'skb->mac' */
    }
#else
    status = pskb_expand_head(skb, 0, PAD_XTRA, GFP_ATOMIC))))
#endif

exit:
    return status;
} /* ipsec_skb_expand */
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__
static int
ipv6_get_ulp(const struct sk_buff *skb, u8 *pProto, int *pAuthHdr)
{
    /* code based on net/ipv6/exthdrs_core.c */
    struct ipv6hdr *iphdr;
    u8 nexthdr;
    int start  = sizeof(struct ipv6hdr);
    int offset = -1;

    iphdr   = ipv6_hdr(skb);
    nexthdr = iphdr->nexthdr;

    if (pProto)
        *pProto = 0xff;
    else
        goto exit;

    if (pAuthHdr)
        *pAuthHdr = 0;

    while (ipv6_ext_hdr(nexthdr))
    {
        struct ipv6_opt_hdr _hdr, *hp;
        int hdrlen;

        if (NEXTHDR_NONE == nexthdr)
            goto exit;

        if (NULL == (hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr)))
            goto exit;

        if (NEXTHDR_FRAGMENT == nexthdr)
        {
            __be16 _frag_off, *fp;
            fp = skb_header_pointer(skb,
                                    start+offsetof(struct frag_hdr, frag_off),
                                    sizeof(_frag_off),
                                    &_frag_off);

            if (NULL == fp)
                goto exit;

            if (ntohs(*fp) & ~0x7)
                break;

            hdrlen = 8;
        }
        else if (NEXTHDR_AUTH == nexthdr)
        {
            if (pAuthHdr)
                *pAuthHdr = 1;

            hdrlen = (hp->hdrlen+2)<<2;
        }
        else
        {
            hdrlen = ipv6_optlen(hp);
        }

        nexthdr = hp->nexthdr;
        start += hdrlen;
    }

    offset = start;
    *pProto = nexthdr;

exit:
    if (0 == offset)
    {
        *pProto = iphdr->nexthdr;
        offset = sizeof(struct ipv6hdr);
    }

    return offset;
}

/*
static int
ipv6_get_ulp(struct sk_buff *skb, u8 *protocol)
{
    int offset;
    struct ipv6hdr *iphdr;
    iphdr = ipv6_hdr(skb);
    *protocol = iphdr->nexthdr;
    offset = ipv6_skip_exthdr(skb, 0, protocol);
    if (offset == -1)
    {
        *protocol = 0xff;
    }
    else if (offset == 0)
    {
        *protocol = iphdr->nexthdr;
        offset = sizeof(struct ipv6hdr);
    }
    return offset;
}
*/
#endif

/*------------------------------------------------------------------*/

static int
ipsec_apply_psk(struct spd *pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
                struct sadb *pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                struct sk_buff **pskb,
#else
                struct sk_buff *skb,
#endif
                int local_out)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#endif
    int status = 0, len, df;

    struct iphdr *iphdr;

#ifdef __ENABLE_DIGICERT_IPV6__
    struct ipv6hdr *ipv6hdr;
    int offset;
#endif

    ubyte2 rlen, roff = 0, hdrm = 0;
    unsigned int bufsize;
    u8 protocol;

    struct ipsecCtx ctx = { 0 };

    /* Extend the buffer out */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    if (skb != (*pskb = skb_share_check(skb, GFP_ATOMIC)))
    {
        /*printk("\n%s (%d): CLONE sk_buff!!!\n", __FUNCTION__, __LINE__);*/
        skb = *pskb; /* cloned! */
    }
#endif

    if (skb_is_nonlinear(skb) || skb_cloned(skb) || (
#ifdef CHECK_HEAD_ROOM
        ((skb_tailroom(skb) < TAIL_XTRA) || !SKB_PUSHABLE(skb)) &&
#endif
        (skb_tailroom(skb) < PAD_XTRA)))
    {
#if 0
        printk("\n%s (%d): EXPAND nonlinear=%d clone=%d hdrm=%d tlrm=%d mlen=%d\n", __FUNCTION__, __LINE__,
               skb_is_nonlinear(skb), skb_cloned(skb),
               skb_headroom(skb), skb_tailroom(skb), skb->mac_len);
#endif
        if (0 > (status = ipsec_skb_expand(skb)))
        {
            ERROR_PRINT(("Can't extend sk_buff for encryption", 0));
            goto exit;
        }
#if 0
        printk("\n%s (%d): EXPANDED hdrm=%d tlrm=%d\n", __FUNCTION__, __LINE__,
               skb_headroom(skb), skb_tailroom(skb));
#endif
    }
#ifdef CHECK_HEAD_ROOM
    /* Move skb->mac */
    else if (SKB_PUSHABLE(skb) && skb_mac_header_was_set(skb))
    {
        ipsec_skb_mmac(skb);
    }
#endif

    /* Set the IP header */
    iphdr = skb_ip_header(skb);
#ifdef __ENABLE_DIGICERT_IPV6__
    if (pxSp->dwDestIP.family == AF_INET6)
    {
        ipv6hdr = ipv6_hdr(skb);
        if ((NULL == ipv6hdr) || ((ubyte *)ipv6hdr != skb->data))
        {
            ERROR_PRINT(("Bad ipv6 packet (out)", 0));
            status = -1;
            goto exit;
        }

        len = ntohs(ipv6hdr->payload_len) + sizeof(struct ipv6hdr);

        if (local_out)
            df = 1; /* need to set skb->local_df for IPv6 fragmentation */
    }
    else
#endif
    {
        if ((NULL == iphdr) || ((ubyte *)iphdr != skb->data))
        {
            ERROR_PRINT(("Bad packet (out)", 0));
            status = -1;
            goto exit;
        }

        len = ntohs(iphdr->tot_len);
        df = iphdr->frag_off & htons(IP_DF);
    }

    if (len > skb->len)
    {
        ERROR_PRINT(("Bad packet (out)", 0));
        status = -1;
        goto exit;
    }
    skb_trim(skb, len);

    /* TCP did not compute correct checksum yet.  It will be done
     * after this but since we start applying IPsec and change
     * the protocol already, it won't be.  So we need to take
     * care of it here (before IPsec also) */
    if (local_out && (CHECKSUM_NONE == skb->ip_summed || CHECKSUM_PARTIAL == skb->ip_summed))
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        if (pxSp->dwDestIP.family == AF_INET6)
        {
            offset = ipv6_get_ulp(skb, &protocol, NULL);
            if (offset == -1)
            {
                ERROR_PRINT(("Failed to find ipv6 transport header (out)", 0));
                status = -1;
                goto exit;
            }
            if (IPPROTO_TCP == protocol)
            {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
                gM_SetTcp6Checksum_ptr(skb->data + offset,
#else
                SetTcp6Checksum(skb->data + offset,
#endif
                                ipv6hdr->saddr.s6_addr, ipv6hdr->daddr.s6_addr,
                                len - offset);
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
            else if (IPPROTO_UDP == protocol)
            {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
                gM_SetUdp6Checksum_ptr(skb->data + offset,
#else
                SetUdp6Checksum(skb->data + offset,
#endif
                                ipv6hdr->saddr.s6_addr, ipv6hdr->daddr.s6_addr);
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
        }
        else
#endif
        {
            protocol = iphdr->protocol;
            if (IPPROTO_TCP == protocol)
            {
                int ihl = iphdr->ihl * 4;

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
                gM_SetTcpChecksum_ptr((unsigned char *)iphdr + ihl,
#else
                SetTcpChecksum((unsigned char *)iphdr + ihl,
#endif
                               ntohl(iphdr->saddr), ntohl(iphdr->daddr),
                               len - ihl);
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
            else if (IPPROTO_UDP == protocol)
            {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
                gM_SetUdpChecksum_ptr((unsigned char *)iphdr + (iphdr->ihl * 4),
#else
                SetUdpChecksum((unsigned char *)iphdr + (iphdr->ihl * 4),
#endif
                               ntohl(iphdr->saddr), ntohl(iphdr->daddr));
                skb->ip_summed = CHECKSUM_UNNECESSARY;
            }
        }
    }

    /* Queue output buffer */
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    goto exit;
#endif

    /* Process output buffer */
#ifdef CHECK_HEAD_ROOM
    if (SKB_PUSHABLE(skb)) hdrm = roff = HEAD_XTRA;
#endif
    bufsize = len + skb_tailroom(skb) + hdrm;

    ctx.pxSp = pxSp;
#ifdef __ENABLE_IPSEC_FLOW__
    ctx.axSaUsed[0] = pxSa;
#endif

#ifdef __ENABLE_DIGICERT_IPV6__
    if (!local_out && (pxSp->dwDestIP.family == AF_INET6))
    {
        if (skb->len + PAD_XTRA > skb->dev->mtu)
        {
            __u32 mtu = skb->dev->mtu - PAD_XTRA;
            DBUG_PRINT(DEBUG_IPSEC,
                       ("Warning: data + ipsec headers exceeds MTU: (%d > %d)",
                        skb->len + PAD_XTRA, skb->dev->mtu));
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34))
            icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
#else
            icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
#endif
            status = ERR_PAYLOAD_TOO_LARGE;
            goto exit;
        }
    }
#endif

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (OK > (status = gM_IPSEC_applyEx_ptr((ubyte *)iphdr - hdrm, (ubyte2)
#else
    if (OK > (status = IPSEC_applyEx((ubyte *)iphdr - hdrm, (ubyte2)
#endif
                                     ((65535 < bufsize) ? 65535 : bufsize),
                                     &rlen, &roff, &ctx)))
    {
        goto exit;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
    if (skb_is_gso(skb))
    {
        /* If GSO is on, must reset it after IPsec encapsulation. */
#if 0
        printk("%s[%d]: len=%d gso(size=%d segs=%d type=%x)\n", __FUNCTION__, __LINE__,
               (int) skb->len,
               (int) skb_shinfo(skb)->gso_size,
               (int) skb_shinfo(skb)->gso_segs,
               (int) skb_shinfo(skb)->gso_type);
#endif
        skb_shinfo(skb)->gso_size = 0;
        skb_shinfo(skb)->gso_segs = 1;
        skb_shinfo(skb)->gso_type = 0;
    }
#endif

#ifdef CHECK_HEAD_ROOM
    if (hdrm && (hdrm != roff))
    {
        unsigned int xhdrlen = hdrm - roff;
        if (HEAD_XTRA < xhdrlen)
        {
            status = -1;
            goto exit;
        }
        skb_push(skb, xhdrlen);
        skb_reset_network_header(skb);
        iphdr = skb_ip_header(skb);
    }
#endif
    skb_put(skb, rlen - skb->len);
#ifdef __ENABLE_DIGICERT_IPV6__
    if (pxSp->dwDestIP.family == AF_INET6)
    {
        offset = ipv6_get_ulp(skb, &protocol, NULL);
        if (offset == -1)
        {
            ERROR_PRINT(("Failed to find ipv6 transport header (out)", 0));
            status = -1;
            DUMP_BYTES((ubyte *)iphdr, rlen, 80, NULL);
            goto exit;
        }
        skb_set_transport_header(skb, offset);
    }
    else
#endif
    {
        skb_set_transport_header(skb, (iphdr->ihl * 4));
    }

    /* Take care of fragmentation for large packets */
    if (df/* && (dst_pmtu(skb_dst(skb)) < rlen)*/)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0))
        skb->local_df = 1; /* hack */
#else
        skb->ignore_df = 1; /* hack */
#endif

#ifdef CHECK_MOD_STATS
    if (modStats.trace)
    {
        DBUG_PRINT(DEBUG_IPSEC,("Status:%d proto:%d len:%d rlen:%d", status, protocol, len, rlen));
        DBUG_PRINT(DEBUG_IPSEC,("Output encrypted packet #%d [len=%d]", modStats.output.applied+1, rlen));
        DUMP_BYTES((ubyte *)iphdr, rlen, 80, NULL);
    }
    if (rlen > modStats.output.maxSize)
    {
        modStats.output.maxSize = rlen;
    }
    modStats.output.bytes += rlen;
    modStats.output.applied++;
#endif

exit:
    return status;
} /* ipsec_apply_psk */


/*------------------------------------------------------------------*/
/* Netfilter IP output/forward hook */

static unsigned int
ipsec_out(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
          void *priv,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
          const struct nf_hook_ops *ops,
#else
          unsigned int hooknum,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
          struct sk_buff **pskb,
#else
          struct sk_buff *skb,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
          const struct nf_hook_state *state)
#else
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn) (struct sk_buff *))
#endif
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    unsigned int hooknum = state->hook;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
    unsigned int hooknum = ops->hooknum;
#endif
#if 0
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    const struct net_device *in = state->in;
    const struct net_device *out = state->out;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
    int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    int (*okfn)(struct sock *, struct sk_buff *) = state->okfn;
#endif
#endif /* 0 */
    int disposition = NF_ACCEPT;
    int status, offset, mf;
    u8  protocol;
    u16 dport, sport;
    MOC_IP_ADDRESS_S daddr, saddr;

    struct spd *pxSp = NULL;
#ifdef __ENABLE_IPSEC_FLOW__
    struct sadb *pxSa = NULL;
#endif
    struct iphdr *iphdr;
#ifdef __ENABLE_DIGICERT_DUAL_MODE__
    int map_id = 0;
    struct iphdr *m_iphdr;
    struct sk_buff *nskb = NULL;
    struct sk_buff *nskb1 =NULL;
    struct sk_buff *encr_nskb =NULL;
    ubyte2 pkt_len = 0;
#endif
    iphdr = skb_ip_header(skb);
    if (NULL == iphdr)
    {
        ERROR_PRINT(("Null packet (out)", 0));
        goto exit;
    }

    protocol = iphdr->protocol;
    offset = ntohs(iphdr->frag_off);
    mf = offset & IP_MF;
    offset &= IP_OFFSET;

#ifdef CHECK_MOD_STATS
    if (modStats.trace)
    {
        DUMP_BYTES((ubyte *)iphdr, skb->len, 80, "Output packet");
    }
#endif

    /* Get TCP/UDP port numbers, if applicable */
    if ((0 == offset) &&
            ((IPPROTO_TCP == protocol) ||
             (IPPROTO_UDP == protocol) ||
             (IPPROTO_ICMP == protocol)))
    {
        int ihl = iphdr->ihl * 4;

        if (skb_is_nonlinear(skb) &&
                (skb_headlen(skb) < (ihl + 4))) /* unlikely */
        {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
            if (skb != (*pskb = skb_share_check(skb, GFP_ATOMIC)))
            {
                /*printk("\n%s (%d): CLONE sk_buff!!!\n", __FUNCTION__, __LINE__);*/
                skb = *pskb; /* cloned! */
            }
#endif
            /*
               printk("\n%s (%d): EXPAND clone=%d hdrm=%d tlrm=%d mlen=%d\n", __FUNCTION__, __LINE__,
               skb_cloned(skb),
               skb_headroom(skb), skb_tailroom(skb), skb->mac_len);
             */
#ifdef CHECK_HEAD_ROOM
            if (0 > (status = ipsec_skb_expand(skb)))
            {
                ERROR_PRINT(("Can't extend sk_buff for encryption", 0));
                goto done;
            }
#else
            if (0 > (status = SKB_LINEARIZE(skb)))
            {
                ERROR_PRINT(("Can't linearize sk_buff for encryption", 0));
                goto done;
            }
#endif
            iphdr = skb_ip_header(skb);
        }

        /* Note that skb->h.raw may be incorrect at this point!!! (< 2.6.22) */
        switch (protocol)
        {
            case IPPROTO_TCP :
                {
                    struct tcphdr *th = (struct tcphdr *)((unsigned char *)iphdr + ihl);
                    sport = ntohs(th->source);
                    dport = ntohs(th->dest);
                    break;
                }
            case IPPROTO_UDP :
                {
                    struct udphdr *uh = (struct udphdr *)((unsigned char *)iphdr + ihl);
                    sport = ntohs(uh->source);
                    dport = ntohs(uh->dest);
                    break;
                }
                /*case IPPROTO_ICMP :*/
            default :
                {
                    u8 *tc = (u8 *)((unsigned char *)iphdr + ihl);
                    sport = ((u16) tc[0] << 8) | (u16) tc[1];
                    dport = 0;
                    break;
                }
        } /* switch */
    }
    else
    {
        dport = sport = 0;
    }

    SET_MOC_IPADDR4(daddr, ntohl(iphdr->daddr));
    SET_MOC_IPADDR4(saddr, ntohl(iphdr->saddr));
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
    DB_PRINT("\n ipsec_out called here for daddr=%x saddr=%x proto=%d",daddr,saddr,protocol);
#endif
    /* Check flow */
#ifdef __ENABLE_IPSEC_FLOW__
    IPSEC_flowGet(&pxSa, &pxSp,
            REF_MOC_IPADDR(daddr), REF_MOC_IPADDR(saddr),
            protocol, dport, sport);

    if (NULL == pxSp)
#endif

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
        if (IPPROTO_UDP == protocol)
        {
            skb_set_transport_header(skb, IPV4_HEADER_SIZE);
            struct udphdr *pxUdp;
            pxUdp = (struct udphdr*)skb_transport_header(skb);
            ubyte2 pwDstPort;
            if(pxUdp != NULL)
            {
                pwDstPort = GET_NTOHS(pxUdp->dest);
            }
            /* get correct entry */
            map_id = ifmap_kern_get_id(iphdr, pwDstPort, FALSE);
            /* no mapping */
            if(-1 == map_id)
            {
                /* forward to normal processing */
                goto process;
            }
            m_mtu = m_ifmap_kern.element[map_id].mtu;
            /* get SPD with multicast dst IP */
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            status = gM_IPSEC_ready_ptr(REF_MOC_IPADDR(
#else
            status = IPSEC_ready(REF_MOC_IPADDR(
#endif
                        ntohl(m_ifmap_kern.element[map_id].multicast_address.v4)),
                    REF_MOC_IPADDR(saddr),
                    protocol, offset, mf,
                    dport, sport, 0, &pxSp, 0, 0);

            if (OK > status)
            {
#ifdef MOCANA_IPSEC_DEBUGGING
                /* For debugging only */
                __be32 ldaddr = m_ifmap_kern.element[map_id].multicast_address.v4;

                /* For debugging only */
                /*-------------------------------------------*/
                printk("IPSEC_ready for multicast failed. status: %d\n", status);
                printk("Inspecting ip header after IPSEC_ready failure. (Note: host byte order)\n");
                printk("daddr: %u.%u.%u.%u\n", ((unsigned char *)&ldaddr)[3], ((unsigned char *)&ldaddr)[2], ((unsigned char *)&ldaddr)[1], ((unsigned char *)&ldaddr)[0]);
                printk("saddr: %u.%u.%u.%u\n", ((unsigned char *)&saddr)[3], ((unsigned char *)&saddr)[2], ((unsigned char *)&saddr)[1], ((unsigned char *)&saddr)[0]);
                /*-------------------------------------------*/
#endif
                goto exit;
            }

            /* copied */
            nskb = skb_copy(skb, GFP_ATOMIC);

            status = ipsec_modify_ip(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                    pskb,
#else
                    nskb,
#endif
                    map_id,
                    FALSE);

            status = ipsec_apply_psk(pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
                    pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                    pskb,
#else
                    nskb,
#endif
                    (NF_HOOK_LOCAL_OUT == hooknum));

            iphdr = skb_ip_header(nskb);
            int len = iphdr->tot_len;
            m_iphdr = iphdr;
            int is_ip_header_present= 1;
            len = GET_NTOHS(len);

            encr_nskb = nskb;
            ubyte count = 0;
            ubyte2 frag_offset = 0;
            pkt_len = nskb->len;
            while(pkt_len > m_mtu)
            {
                /* fragment the Ip packet here such as the AH header will be added to last fragment*/
                nskb1 = alloc_skb(pkt_len - m_mtu + 50, GFP_KERNEL);
                skb_reserve(nskb1, 50); /* reserver 50 bytes for IP and EThernet header*/
                if(!is_ip_header_present)
                {
                    /* add ip header at begining of the packet*/
                    struct iphdr *iph;
                    skb_split(nskb, nskb1 , m_mtu - IPV4_HEADER_SIZE);
                    skb_push(nskb, sizeof(struct iphdr));
                    skb_reset_network_header(nskb);
                    iph = skb_ip_header(nskb);
                    iph->version = m_iphdr->version;
                    iph->ihl = m_iphdr->ihl;
                    iph->tos = m_iphdr->tos;
                    iph->tot_len = htons(m_mtu);
                    frag_offset = (count * (m_mtu - IPV4_HEADER_SIZE))/8;
                    iph->frag_off = ntohs(frag_offset | (1<<13));
                    iph->id = m_iphdr->id;
                    iph->ttl = m_iphdr->ttl;
                    iph->protocol = m_iphdr->protocol; /* IPPROTO_UDP in this case */
                    iph->saddr = m_iphdr->saddr;
                    iph->daddr = m_iphdr->daddr;
                    ip_send_check(iph);
                    nskb->ip_summed = encr_nskb->ip_summed;
                    nskb->priority = encr_nskb->priority;
                    nskb->protocol = encr_nskb->protocol;
                }
                else
                {
                    /* update the ip header*/
                    skb_split(nskb, nskb1 , m_mtu);
                    iphdr->frag_off = htons(1<<13);
                    iphdr->tot_len = htons(m_mtu);
                    /* generate checksum for the IP packet*/
                    ip_send_check(iphdr);
                }

                /* transmit multicast packet */
                status = ipsec_add_eth(pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
                        pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                        pskb,
#else
                                 nskb,
#endif
                                 (NF_HOOK_LOCAL_OUT == hooknum),
                                 map_id);
                if(!is_ip_header_present)   /* first packet should be preserved till all packets have been created*/
                {
                    dev_kfree_skb(nskb);
                }
                nskb = nskb1;
                pkt_len = nskb->len + IPV4_HEADER_SIZE;
                is_ip_header_present = 0;
                count++;
            }

            if(!is_ip_header_present)
            {
                /* add ip header at begining of the packet*/
                struct iphdr *iph;

                skb_push(nskb, sizeof(struct iphdr));
                skb_reset_network_header(nskb);
                iph = skb_ip_header(nskb);
                iph->version = m_iphdr->version;
                iph->ihl = m_iphdr->ihl;
                iph->tos = m_iphdr->tos;
                iph->tot_len = htons(nskb->len);
                /* generate IP poacket fragment offset*/
                frag_offset = (count * (m_mtu - IPV4_HEADER_SIZE))/8;

                iph->frag_off = htons(frag_offset);
                iph->id = m_iphdr->id;
                iph->ttl = m_iphdr->ttl;
                iph->protocol = m_iphdr->protocol; /* IPPROTO_UDP in this case */
                iph->saddr = m_iphdr->saddr;
                iph->daddr = m_iphdr->daddr;

                /* generate checksum for the IP packet*/
                ip_send_check(iph);
                nskb->ip_summed = encr_nskb->ip_summed;
                nskb->priority = encr_nskb->priority;
                nskb->protocol = encr_nskb->protocol;
            }
            /* transmit multicast packet */
            status = ipsec_add_eth(pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
                    pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                    pskb,
#else
                    nskb,
#endif
                    (NF_HOOK_LOCAL_OUT == hooknum),
                    map_id);


            if(encr_nskb != nskb)   /* Make sure packet has been fragmented and nskb is a new buffer other than base buffer*/
            {
                dev_kfree_skb(encr_nskb);
            }
            dev_kfree_skb(nskb);
            /* Hand original skb which contains the broadcast over
             * to network stack. Exit to circumvent normal processing below */
            if(m_ifmap_kern.element[map_id].drop_original_pkt)
            {
		disposition = NF_DROP; /* Drop original packet here*/
            }
            else
            {
                disposition = NF_ACCEPT;
            }
            goto exit;
    }

process:
#endif

    /* Check if IPsec is needed in order to avoid
       reassembly, checksum, etc.. */

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (OK > (status = gM_IPSEC_ready_ptr(REF_MOC_IPADDR(daddr),
#else
    if (OK > (status = IPSEC_ready(REF_MOC_IPADDR(daddr),
#endif
                    REF_MOC_IPADDR(saddr),
                    protocol, offset, mf,
                    dport, sport, 0, &pxSp, 0, 0)))
    {
        /* Check unsecured forwarded packets */
        if ((NF_HOOK_FORWARD == hooknum) &&
                (STATUS_IPSEC_BYPASS == status))
        {

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            if (OK == (status = gM_IPSEC_ready_ptr(REF_MOC_IPADDR(daddr),
#else
            if (OK == (status = IPSEC_ready(REF_MOC_IPADDR(daddr),
#endif
                            REF_MOC_IPADDR(saddr),
                            protocol, offset, mf,
                            dport, sport, 1, NULL, 0, 0)))
            {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
                DB_PRINT("\n ipsec_out 2nd ready failed with status=%d",status);
#endif
                status = ERR_IPSEC_DROP;
            }
        }
        goto done;
    }

    /* transmit modified and encrypted packet */
    status = ipsec_apply_psk(pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
            pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
            pskb,
#else
            skb,
#endif
            (NF_HOOK_LOCAL_OUT == hooknum));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    skb = *pskb;
#endif

done:
    switch (status)
    {
        case OK:
#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
            ipsec_async_piggyback_flow(skb, pxSp, pxSa);
            disposition = NF_QUEUE;
#endif

#if 0 /* enable if NAT is on the same host as IPsec */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
            if (IPSEC_MODE_TUNNEL == pxSp->oMode)
            {
                /*
                   iphdr = skb_ip_header(skb);
                   DUMP_BYTES((ubyte *)iphdr, ntohs(iphdr->tot_len), 80, "Output packet");
                   DBUG_PRINT(DEBUG_IPSEC,("[proto:%d, sum=%d, len=%d]", iphdr->protocol, skb->ip_summed, ntohs(iphdr->tot_len)));
                 */

                nf_reset(skb);
                if (NULL != skb_dst(skb) && NULL != (skb_dst(skb)->ops))
                    skb_dst(skb)->ops->local_out(skb);
            }
#endif
#endif /* #if 0 */

        case STATUS_IPSEC_BYPASS:
            break;

        default:
#ifdef CHECK_MOD_STATS
            modStats.output.errors++;
            modStats.output.lastErr = status;
            ERROR_PRINT(("IPSEC_apply error: status is %d", status));
#endif
            disposition = NF_DROP;
            break;
    }

exit:
#ifdef CHECK_MOD_STATS
    modStats.output.all++;
#endif
    if(status != -8810)
    {
#ifdef __ENABLE_DIGICERT_IPSEC_FLOW_DEBUGGING__
        DB_PRINT("\n ipsec_out end with status=%d disposition=%d",status, disposition);
#endif
    }
    return disposition;
} /* ipsec_out */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__

static unsigned int
ipsec6_in(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
          void *priv,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
          const struct nf_hook_ops *ops,
#else
          unsigned int hooknum,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
          struct sk_buff **pskb,
#else
          struct sk_buff *skb,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
          const struct nf_hook_state *state)
#else
          const struct net_device *in,
          const struct net_device *out,
          int (*okfn) (struct sk_buff *))
#endif
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#endif
#if 0
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    unsigned int hooknum = state->hook;
    const struct net_device *in = state->in;
    const struct net_device *out = state->out;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
    unsigned int hooknum = ops->hooknum;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
    int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    int (*okfn)(struct sock *, struct sk_buff *) = state->okfn;
#endif
#endif /* 0 */
    int disposition = NF_ACCEPT;
    int status, offset, len, hasAuthHdr;
    u8  protocol;
    u16 dport, sport;
    MOC_IP_ADDRESS_S daddr, saddr;

    struct ipv6hdr *iphdr;
    struct spd *pxSp;
    #ifdef __ENABLE_DIGICERT_DUAL_MODE__
    int map_id = 0;
    #endif
    /* Linearize the buffer */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    if (skb_shared(skb))
    {
        /* printk("\n%s (%d): COPY sk_buff!!!\n", __FUNCTION__, __LINE__); */
        *pskb = skb_copy(skb, GFP_ATOMIC);
        kfree_skb(skb);
        skb = *pskb;
    }
    else
#endif
    if (skb_is_nonlinear(skb) || skb_cloned(skb))
    {
        if (0 > SKB_LINEARIZE(skb))
        {
            ERROR_PRINT(("Can't linearize packet (in6)", 0));
            disposition = NF_DROP;
            goto exit;
        }
    }

    /* Set the IP header */
    iphdr = ipv6_hdr(skb);
    if ((NULL == iphdr) || ((ubyte *)iphdr != skb->data))
    {
        ERROR_PRINT(("Bad packet (in6)", 0));
        disposition = NF_DROP;
        goto exit;
    }

    len = ntohs(iphdr->payload_len) + sizeof(struct ipv6hdr);
    if (len > skb->len)
    {
        ERROR_PRINT(("Bad packet (in6)", 0));
        disposition = NF_DROP;
        goto exit;
    }
    skb_trim(skb, len);

    offset = ipv6_get_ulp(skb, &protocol, &hasAuthHdr);
    if (offset == -1)
    {
        ERROR_PRINT(("Failed to find transport header (in6)", 0));
        disposition = NF_DROP;
        goto exit;
    }

    /* Note that skb->h.raw may be incorrect at this point!!! (< 2.6.22) */
    switch (protocol)
    {
    case IPPROTO_TCP :
    {
        struct tcphdr *th = (struct tcphdr *)((unsigned char *)iphdr + offset);
        sport = ntohs(th->source);
        dport = ntohs(th->dest);
        break;
    }
    case IPPROTO_UDP :
    {
        struct udphdr *uh = (struct udphdr *)((unsigned char *)iphdr + offset);
        sport = ntohs(uh->source);
        dport = ntohs(uh->dest);
        break;
    }
    case IPPROTO_ICMPV6 :
    {
        u8 *tc = (u8 *)((unsigned char *)iphdr + offset);
        sport = ((u16) tc[0] << 8) | (u16) tc[1];
        dport = 0;
        break;
    }
    default :
    {
        dport = sport = 0;
    }
    }

    SET_MOC_IPADDR6_GPL(daddr, iphdr->daddr.s6_addr);
    SET_MOC_IPADDR6_GPL(saddr, iphdr->saddr.s6_addr);

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
    /* dual-mode receive */
    if (IPPROTO_ESP || hasAuthHdr)
    {
        /* Process input buffer */

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_permitEx_ptr((ubyte *)iphdr, (ubyte2)len,
#else
        status = IPSEC_permitEx((ubyte *)iphdr, (ubyte2)len,
#endif
                            &rlen, &roff, &ctx);

        switch (status)
        {
        case OK:
            if (0 != roff)
            {
                skb_pull(skb, roff);
                skb_reset_network_header(skb);
                iphdr = skb_ip_header(skb);
            }
            skb_trim(skb, rlen);
            skb_set_transport_header(skb, (iphdr->ihl * 4));

            if (IPSEC_MODE_TUNNEL == ctx.pxSp->oMode) /* !!! */
            {
                skb_dst_drop(skb);

                if (ip_route_input(skb, iphdr->daddr, iphdr->saddr, iphdr->tos, skb->dev))
                {
                DB_PRINT("\n ipsec_in calling dropped here");
                    disposition = NF_DROP;
                    break;
                }
                else /* forwarding */
                {
                    /* dst_output() does not involve NF_HOOK_FORWARD. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
                    dst_output(skb);
#else
                    dst_output(&init_net, skb->sk, skb);
#endif
                DB_PRINT("\n ipsec_in stolen");
                    disposition = NF_STOLEN;
                }
            }

            if (IPPROTO_UDP == iphdr->protocol)
            {
                /* get correct entry */
                map_id = ifmap_kern_get_id6(iphdr, TRUE);

                /* no mapping */
                if(-1 == map_id)
                {
                    /* failure */
                    disposition = NF_DROP;
                    goto exit;
                }

                /* alter ip csum and finish */
                status = ipsec_modify_ip(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                                         pskb,
#else
                                         skb,
#endif
                                         map_id,
                                         TRUE);

                printk("ipsec6_in called for multicast packet. Inbound IPv6 Checksum altered. Broadcast Address set\n");
            }
        }
    }
#endif
    /* Check for clear text packet */

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    status = gM_IPSEC_ready_ptr(REF_MOC_IPADDR(daddr),
#else
    status = IPSEC_ready(REF_MOC_IPADDR(daddr),
#endif
                         REF_MOC_IPADDR(saddr),
                         protocol, 0, 0,
                         dport, sport, TRUE, &pxSp, 0, 0);

    /* printk("ipsec6_in - IPSEC_ready status: %d (protocol %d %d)\n", status, protocol, hasAuthHdr); */

    if ((OK == status) &&
        (IPPROTO_ESP == protocol || hasAuthHdr ||
         IPPROTO_FRAGMENT == protocol || IPPROTO_ICMPV6 == protocol ||
         (IPSEC_MODE_TUNNEL == pxSp->oMode && !SAME_MOC_IPADDR_GPL(REF_MOC_IPADDR(daddr), pxSp->dwTunlDestIP))) ) /* !!! */
    {
        status = STATUS_IPSEC_BYPASS;
    }

    switch (status)
    {
    case STATUS_IPSEC_BYPASS:
        break;

    case OK:
    default:
        disposition = NF_DROP;
        break;
    }

exit:
    return disposition;
} /* ipsec6_in */


/*------------------------------------------------------------------*/

static unsigned int
ipsec6_out(
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
           void *priv,
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
           const struct nf_hook_ops *ops,
#else
           unsigned int hooknum,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
           struct sk_buff **pskb,
#else
           struct sk_buff *skb,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
           const struct nf_hook_state *state)
#else
           const struct net_device *in,
           const struct net_device *out,
           int (*okfn) (struct sk_buff *))
#endif
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    unsigned int hooknum = state->hook;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0))
    unsigned int hooknum = ops->hooknum;
#endif
#if 0
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    const struct net_device *in = state->in;
    const struct net_device *out = state->out;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
    int (*okfn)(struct net *, struct sock *, struct sk_buff *) = state->okfn;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    int (*okfn)(struct sock *, struct sk_buff *) = state->okfn;
#endif
#endif /* 0 */
    int disposition = NF_ACCEPT;
    int status, offset;
    u8  protocol;
    u16 dport, sport;
    MOC_IP_ADDRESS_S daddr, saddr;

    struct spd *pxSp = NULL;
    struct ipv6hdr *iphdr = ipv6_hdr(skb);

    if (NULL == iphdr)
    {
        ERROR_PRINT(("Null packet (out6)", 0));
        goto exit;
    }

    /* Get TCP/UDP port numbers, if applicable */
    offset = ipv6_get_ulp(skb, &protocol, NULL);
    if (offset == -1)
    {
        ERROR_PRINT(("Failed to find transport header (out6)", 0));
        status = -1;
        goto done;
    }

    if (skb_is_nonlinear(skb) &&
        (skb_headlen(skb) < (offset + 4)) && /* unlikely */
        ((IPPROTO_TCP == protocol) ||
         (IPPROTO_UDP == protocol) ||
         (IPPROTO_ICMPV6 == protocol)))
    {
#if 0
        printk("%s[%d]: iphdr_len=%d head_len=%d data_len=%d len=%d frag_list=%p\n",
               __FUNCTION__, __LINE__,
               offset, (int) skb_headlen(skb), (int) skb->data_len, (int)skb->len,
               skb_shinfo(skb)->frag_list);
#endif
        ERROR_PRINT(("Failed to find transport header ports (out6)", 0));
        dport = sport = 0;
        goto ready;
    }

    /* Note that skb->h.raw may be incorrect at this point!!! (< 2.6.22) */
    switch (protocol)
    {
    case IPPROTO_TCP :
    {
        struct tcphdr *th = (struct tcphdr *)((unsigned char *)iphdr + offset);
        sport = ntohs(th->source);
        dport = ntohs(th->dest);
        break;
    }
    case IPPROTO_UDP :
    {
        struct udphdr *uh = (struct udphdr *)((unsigned char *)iphdr + offset);
        sport = ntohs(uh->source);
        dport = ntohs(uh->dest);
        break;
    }
    case IPPROTO_ICMPV6 :
    {
        /* Note that skb_transport_header(skb) may be NULL */
        u8 *tc = (u8 *)iphdr;
        tc = tc + offset;
        sport = ((u16) tc[0] << 8) | (u16) tc[1];
        dport = 0;
        break;
    }
    default :
    {
        dport = sport = 0;
    }
    }

ready:
    SET_MOC_IPADDR6_GPL(daddr, iphdr->daddr.s6_addr);
    SET_MOC_IPADDR6_GPL(saddr, iphdr->saddr.s6_addr);

#ifdef __ENABLE_DIGICERT_DUAL_MODE__
    if (IPPROTO_UDP == protocol)
    {
        /* get correct entry */
        map_id = ifmap_kern_get_id6(iphdr, TRUE);

        /* no mapping */
        if(-1 == map_id)
        {
            /* forward to normal processing */
            goto process;
        }

        /* get SPD with multicast dst IP */

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        status = gM_IPSEC_ready_ptr(REF_MOC_IPADDR(
#else
        status = IPSEC_ready(REF_MOC_IPADDR(
#endif
                           ntohl(m_ifmap_kern.element[map_id].multicast_address.v4)),
                           REF_MOC_IPADDR(saddr),
                           protocol, offset, mf,
                           dport, sport, 0, &pxSp, 0, 0);
        if (OK > status)
        {
            goto exit;
        }

        struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
        status = ipsec_modify_ip(
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                                 pskb,
#else
                                 nskb,
#endif
                                 map_id,
                                 TRUE);

        status = ipsec_apply_psk(pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
                                 pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                                 pskb,
#else
                                 nskb,
#endif
                                 (NF_HOOK_LOCAL_OUT == hooknum));

        /* transmit multicast packet */
        status = ipsec_add_eth(pxSp,
#ifdef __ENABLE_IPSEC_FLOW__
                                 pxSa,
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                                 pskb,
#else
                                 nskb,
#endif
                                 (NF_HOOK_LOCAL_OUT == hooknum),
                                 map_id);

        /* Hand original skb which contains the broadcast over
         * to network stack. Exit to circumvent normal processing below */
        disposition = NF_ACCEPT;
        goto done;
    }

process:
#endif
    /* Check if IPsec is needed in order to avoid reassembly, checksum, etc.. */

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    status = gM_IPSEC_ready_ptr(REF_MOC_IPADDR(daddr),
#else
    status = IPSEC_ready(REF_MOC_IPADDR(daddr),
#endif
                         REF_MOC_IPADDR(saddr),
                         protocol, 0, 0,
                         dport, sport, 0, &pxSp, 0, 0);
    if (OK > status)
    {
        goto done;
    }

    status = ipsec_apply_psk(pxSp,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                             pskb,
#else
                             skb,
#endif
                             (NF_HOOK_LOCAL_OUT == hooknum));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    skb = *pskb;
#endif

done:
    switch (status)
    {
    case OK:
    case STATUS_IPSEC_BYPASS:
        break;

    default:
        DBUG_PRINT(DEBUG_IPSEC, ("Failed to encrypt packet: %d", status));
        disposition = NF_DROP;
        break;
    }

exit:
    return disposition;
} /* ipsec6_out */

#endif /* __ENABLE_DIGICERT_IPV6__ */


/*------------------------------------------------------------------*/

static int
ipsec_open(struct inode *inode, struct file *file)
{
    file->private_data = &modStats;
    return OK;
}

static struct nf_hook_ops ipsec_ops[] =
{
    {
     .hook     = ipsec_out,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET,
     .hooknum  = NF_HOOK_LOCAL_OUT,
     .priority = NF_IP_PRI_IPSEC,
     },
    {
     .hook     = ipsec_in,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET,
     .hooknum  = NF_HOOK_LOCAL_IN,
     .priority = NF_IP_PRI_IPSEC,
     },
    {
     .hook     = ipsec_out,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET,
     .hooknum  = NF_HOOK_FORWARD,
     .priority = NF_IP_PRI_IPSEC,
     },

#ifdef __ENABLE_DIGICERT_IPV6__
    {
     .hook     = ipsec6_out,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET6,
     .hooknum  = NF_HOOK_LOCAL_OUT,
     .priority = NF_IP_PRI_IPSEC,
     },
    {
     .hook     = ipsec6_out,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET6,
     .hooknum  = NF_HOOK_FORWARD,
     .priority = NF_IP_PRI_IPSEC,
     },
#if 0
    {
     .hook     = ipsec6_out,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET6,
     .hooknum  = NF_HOOK_POST_ROUTE,
     .priority = NF_IP_PRI_IPSEC,
     },
#endif
    {
     .hook     = ipsec6_in,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
     .owner    = THIS_MODULE,
#endif
     .pf       = PF_INET6,
     .hooknum  = NF_HOOK_PRE_ROUTE,
     .priority = NF_IP_PRI_IPSEC,
     }

#endif /* __ENABLE_DIGICERT_IPV6__ */

};

/* table of callbacks */
static struct file_operations ipsecOperations =
{
    .owner = THIS_MODULE,
#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)) )
    .unlocked_ioctl = ipsec_ioctl,
    .compat_ioctl = ipsec_compat_ioctl,
#else
    .ioctl = ipsec_ioctl,
#endif
    .open  = ipsec_open,
};


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
static int ipsec6_rcv(struct sk_buff **pskb)
#else
static int ipsec6_rcv(struct sk_buff *skb)
#endif
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    struct sk_buff *skb = *pskb;
#endif

    int           status = -1;
    ubyte2        rlen, roff = 0;
    int           len, thdr_offset, hasAuthHdr;
    ubyte         protocol;

    struct ipsecCtx ctx = { 0 };

    struct ipv6hdr *iphdr;

    /* pskb_pull is called before this handler
       (in ip6_input.c), but we need the ipv6 header */
    if (!skb_push(skb, sizeof(struct ipv6hdr)))
    {
        goto exit;
    }

    /* Linearize the buffer */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    if (skb_shared(skb))
    {
        /* printk("\n%s (%d): COPY sk_buff!!!\n", __FUNCTION__, __LINE__); */
        *pskb = skb_copy(skb, GFP_ATOMIC);
        kfree_skb(skb);
        skb = *pskb;
    }
    else
#endif
    if (skb_is_nonlinear(skb) || skb_cloned(skb))
    {
        if (0 > SKB_LINEARIZE(skb))
        {
            ERROR_PRINT(("Can't linearize packet (in6)", 0));
            goto exit;
        }
    }

    /* Set the IP header */
    iphdr = ipv6_hdr(skb);
    if ((NULL == iphdr) || ((ubyte *)iphdr != skb->data))
    {
        ERROR_PRINT(("Bad packet (in6)", 0));
        goto exit;
    }

    len = ntohs(iphdr->payload_len) + sizeof(struct ipv6hdr);
    if (len > skb->len)
    {
        ERROR_PRINT(("Bad packet (in6)", 0));
        goto exit;
    }
    skb_trim(skb, len);

    /* Process input buffer */
    /* Note: Wireshark may report corrupted packets if
       pwOffset is set. For debugging purpose, pwOffset
       can be set to NULL. */

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    status = gM_IPSEC_permitEx_ptr((ubyte *)iphdr, (ubyte2)len,
#else
    status = IPSEC_permitEx((ubyte *)iphdr, (ubyte2)len,
#endif
                            &rlen, &roff, &ctx);

    switch (status)
    {
    case OK:
        if (0 != roff)
        {
            skb_pull(skb, roff);
            skb_reset_network_header(skb);
            iphdr = ipv6_hdr(skb);

            if (skb_mac_header_was_set(skb))
            {
                unsigned char *mac = (ubyte *)iphdr - skb->mac_len;
                if (mac > skb_mac_header(skb))
                {
                    if (skb->mac_len)
                        memmove(mac, skb_mac_header(skb), skb->mac_len);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
                    skb->mac.raw = mac;
#else
                    skb_set_mac_header(skb, -(skb->mac_len));
#endif
                }
            }
        }
        skb_trim(skb, rlen);

        thdr_offset = ipv6_get_ulp(skb, &protocol, NULL);
        if (thdr_offset == -1)
        {
            ERROR_PRINT(("Failed to find transport header (in6)", 0));
            status = -1;
            goto exit;
        }
        skb_set_transport_header(skb, thdr_offset);

        if (IPSEC_MODE_TUNNEL == ctx.pxSp->oMode)
        {
            MOC_IP_ADDRESS_S daddr;

            SET_MOC_IPADDR6_GPL(daddr, iphdr->daddr.s6_addr);
            if (SAME_MOC_IPADDR_GPL(REF_MOC_IPADDR(daddr), ctx.pxSp->dwTunlDestIP))
            {
                /* local delivery */
                break;
            }

            /* re-route packet */
            skb_dst_drop(skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
            nf_reset(skb);
#else
            nf_reset_ct(skb);
#endif
            netif_rx(skb);
            status = -1;
        }

        break;

    case STATUS_IPSEC_BYPASS:
        if ( (0 <= ipv6_get_ulp(skb, &protocol, &hasAuthHdr)) &&
             (IPPROTO_ESP == protocol || hasAuthHdr) )
        {
            /* do not resubmit ESP or AH packet */
            status = -1;
            goto exit;
        }

        status = OK;
        break;

    default:
        DBUG_PRINT(DEBUG_IPSEC,("IPSEC_permit error: status is %d, len=%d", status, len));
        break;
    }

exit:

#if 0
    /* !!! Do we need skb_pull? */
    if (IPSEC_MODE_TUNNEL != ctx.pxSp->oMode)
    {
        if (!skb_pull(skb, sizeof(struct ipv6hdr)))
            status = -1;
    }
#endif

    /*
     * Return values (see net/ipv6/ip6_input.c):
     *  1 - continue IPv6 extension header processing
     *  0 - deliver the packet?
     * -1 - discard
     */
    return (0 <= status) ? 1 : -1;

} /* ipsec6_rcv */


/*------------------------------------------------------------------*/

static const struct inet6_protocol ipsec6_protocol = {
    .handler = ipsec6_rcv,
    .flags   = INET6_PROTO_NOPOLICY,
};

#endif /* __ENABLE_DIGICERT_IPV6__ */


/*------------------------------------------------------------------*/

extern sbyte4 IKE_setIkeSettings(sbyte4 (*setIkeSettings)(void *));

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)

#include <linux/kprobes.h>
#include <linux/kallsyms.h>

typedef struct class * (*g_class_create_funcptr)(struct module *, const char *name);

g_class_create_funcptr myFuncPtr = NULL;
g_class_create_funcptr gM_class_create_ptr;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

#define __M_RESOLVE_SYMBOL(symbolName,isFatal)						\
	gM_##symbolName##_ptr = DIGI_resolveSymbol(#symbolName);			\
    if ( NULL == gM_##symbolName##_ptr )	                        \
    {                                                               \
        if (isFatal) return -1;                                     \
    }						                                        \
    else                                                            \
    {                                                               \
                                                           \
    }

#define KPROBE_LOOKUP 1
#define __M_RESOLVE_SYMBOL_REQUIRED(symbolName) __M_RESOLVE_SYMBOL(symbolName,1)

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static kallsyms_lookup_name_t getkAllSymsLookUpNameMethod(void)
{
    kallsyms_lookup_name_t kallSymsLookupNameMethod = NULL;

#ifdef KPROBE_LOOKUP
    register_kprobe(&kp);
    kallSymsLookupNameMethod = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#else
    kallSymsLookupNameMethod = kallsyms_lookup_name;
#endif

    return kallSymsLookupNameMethod;
}

static void* DIGI_resolveSymbol(const char* symbolName )
{
    kallsyms_lookup_name_t kallSymsLookupNameMethod = getkAllSymsLookUpNameMethod();
    if (kallSymsLookupNameMethod)
    {
        unsigned long address = kallSymsLookupNameMethod(symbolName);
        return (void*)address;
    }
    else
    {
        printk("getkAllSymsLookUpNameMethod failed\n");
        return NULL;
    }
}

static int resolve_external_symbols()
{
    int rc = -1;

	__M_RESOLVE_SYMBOL_REQUIRED(DIGICERT_initialize);
    if (!gM_DIGICERT_initialize_ptr)
    {
        printk("DIGICERT_initialize resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyFlush);
    if (!gM_IPSEC_keyFlush_ptr)
    {
        printk("IPSEC_keyFlush resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(DIGICERT_freeDigicert);
    if (!gM_DIGICERT_freeDigicert_ptr)
    {
        printk("DIGICERT_freeDigicert resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_setIkeSettings);
    if (!gM_IPSEC_setIkeSettings_ptr)
    {
        printk("IPSEC_setIkeSettings resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_groupKeyAdd);
    if (!gM_IPSEC_groupKeyAdd_ptr)
    {
        printk("IPSEC_groupKeyAdd resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_confAdd1);
    if (!gM_IPSEC_confAdd1_ptr)
    {
        printk("IPSEC_confAdd1 resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_enumSa);
    if (!gM_IPSEC_enumSa_ptr)
    {
        printk("IPSEC_enumSa resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(queue_put_tail);
    if (!gM_queue_put_tail_ptr)
    {
        printk("queue_put_tail resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_confFlush);
    if (!gM_IPSEC_confFlush_ptr)
    {
        printk("IPSEC_confFlush resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(DIGI_MEMSET);
    if (!gM_DIGI_MEMSET_ptr)
    {
        printk("DIGI_MEMSET resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(DIGI_MEMCPY);
    if (!gM_DIGI_MEMCPY_ptr)
    {
        printk("DIGI_MEMCPY resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyGet);
    if (!gM_IPSEC_keyGet_ptr)
    {
        printk("IPSEC_keyGet resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyGetEx);
    if (!gM_IPSEC_keyGetEx_ptr)
    {
        printk("IPSEC_keyGetEx resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyDelete);
    if (!gM_IPSEC_keyDelete_ptr)
    {
        printk("IPSEC_keyDelete resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_flush);
    if (!gM_IPSEC_flush_ptr)
    {
        printk("IPSEC_flush resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_applyEx);
    if (!gM_IPSEC_applyEx_ptr)
    {
        printk("IPSEC_applyEx resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(SetTcpChecksum);
    if (!gM_SetTcpChecksum_ptr)
    {
        printk("SetTcpChecksum resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(SetUdpChecksum);
    if (!gM_SetUdpChecksum_ptr)
    {
        printk("SetUdpChecksum resolution failed\n");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
	__M_RESOLVE_SYMBOL_REQUIRED(SetUdp6Checksum);
    if (!gM_SetUdp6Checksum_ptr)
    {
        printk("SetUdp6Checksum resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(SetTcp6Checksum);
    if (!gM_SetUdp6Checksum_ptr)
    {
        printk("SetTcp6Checksum resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(CmpIpAddr6);
    if (!gM_CmpIpAddr6_ptr)
    {
        printk("CmpIpAddr6 resolution failed\n");
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_IPV6__ */

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_permitEx);
    if (!gM_IPSEC_permitEx_ptr)
    {
        printk("IPSEC_permitEx resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyAdd);
    if (!gM_IPSEC_keyAdd_ptr)
    {
        printk("IPSEC_keyAdd resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyAddEx);
    if (!gM_IPSEC_keyAddEx_ptr)
    {
        printk("IPSEC_keyAddEx resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyInitiate);
    if (!gM_IPSEC_keyInitiate_ptr)
    {
        printk("IPSEC_keyInitiate resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_ready);
    if (!gM_IPSEC_ready_ptr)
    {
        printk("IPSEC_ready resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_init);
    if (!gM_IPSEC_init_ptr)
    {
        printk("IPSEC_init resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyReady);
    if (!gM_IPSEC_keyReady_ptr)
    {
        printk("IPSEC_keyReady resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_getSpd);
    if (!gM_IPSEC_getSpd_ptr)
    {
        printk("IPSEC_getSpd resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_confDelete);
    if (!gM_IPSEC_confDelete_ptr)
    {
        printk("IPSEC_confDelete resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(DIGI_deltaMS);
    if (!gM_DIGI_deltaMS_ptr)
    {
        printk("DIGI_deltaMS resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(register_unload_callback);
    if (!gM_register_unload_callback_ptr)
    {
        printk("register_unload_callback resolution failed\n");
        goto exit;
    }

	__M_RESOLVE_SYMBOL_REQUIRED(IPSEC_keyFlush);
    rc = 0;

exit:
    return rc;
}
#endif

static void moc_ipsec_cleanup_module(void)
{
    if (!module_unloaded)
    {
        synchronize_net();

#ifdef __ENABLE_DIGICERT_IPV6__
        inet6_del_protocol(&ipsec6_protocol, IPPROTO_ESP);
        inet6_del_protocol(&ipsec6_protocol, IPPROTO_AH);
#endif

        NF_UNREGISTER_HOOKS(ipsec_ops);

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
        ipsec_async_cleanup();
#endif

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_IPSEC_flush_ptr();
#else
        IPSEC_flush();
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
        PFKEY_cleanup();
#endif

#if !defined(__DISABLE_DIGICERT_INIT__)
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGICERT_freeDigicert_ptr();
#else
        DIGICERT_freeDigicert();
#endif
#endif

        module_unloaded = 1;
    }
}

/*------------------------------------------------------------------*/
static void unload_callback(void)
{
    printk("moc_ipsec unloaded, disable ipsec ...\n");
    moc_ipsec_cleanup_module();
}

/*------------------------------------------------------------------*/
static int __init
mss_ipsec_init(void)
{
    int status = 0;
    int phase = 0;

#if !defined(__DISABLE_DIGICERT_INIT__)
    InitMocanaSetupInfo setupInfo;
#endif

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (resolve_external_symbols() < 0)
    {
        printk("External symbols resolution failed\n");
        status = -EIO;
        return status;
    }

    // Register unload
    gM_register_unload_callback_ptr(unload_callback);

#endif

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
    if (0 > (mIPsecDevMajor = register_chrdev(0, IPSC_NAME, &ipsecOperations)))
#else
    if (0 > register_chrdev(IPSC_MAJOR, IPSC_NAME, &ipsecOperations))
#endif
    {
        printk("Register chrdev failed\n");
        status = -EIO;
        goto cleanup;
    }

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0))
    mIPsecDevClass = class_create(IPSC_NAME);
#else
    mIPsecDevClass = class_create(THIS_MODULE, IPSC_NAME);
#endif
    device_create(mIPsecDevClass, NULL, MKDEV(mIPsecDevMajor, 1), "%s", IPSC_NAME);
#endif

    phase = 1;
#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
    printk("IPsec device registration for %s (major=%d) succeed\n",
           IPSC_NAME, mIPsecDevMajor);
#else
    printk("IPsec device registration for %s (major=%d) succeed\n",
           IPSC_NAME, IPSC_MAJOR);
#endif


#if !defined(__DISABLE_DIGICERT_INIT__)
    setupInfo.MocSymRandOperator = NULL;
    setupInfo.pOperatorInfo = NULL;
    setupInfo.pStaticMem = 0;
    setupInfo.staticMemSize = 0;
    /*
     * This does NOT make IPSEC single threaded. This removes the mutex
     * from the crypto interface MocContext.
     */
    setupInfo.flags = MOC_INIT_FLAG_SINGLE_THREAD;
    setupInfo.pDigestOperators = NULL;
    setupInfo.digestOperatorCount = 0;
    setupInfo.pSymOperators = NULL;
    setupInfo.symOperatorCount = 0;
    setupInfo.pKeyOperators = NULL;
    setupInfo.keyOperatorCount = 0;
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (0 > (status = gM_DIGICERT_initialize_ptr(&setupInfo, NULL)))
#else
    if (0 > (status = DIGICERT_initialize(&setupInfo, NULL)))
#endif
    {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGICERT_freeDigicert_ptr();
#else
        DIGICERT_freeDigicert();
#endif
        goto cleanup;
    }
#endif
#ifdef __ENABLE_DIGICERT_IKE_SERVER__
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (0 > (status = IKE_setIkeSettings(gM_IPSEC_setIkeSettings_ptr)))
#else
    if (0 > (status = IKE_setIkeSettings(IPSEC_setIkeSettings)))
#endif
    {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGICERT_freeDigicert_ptr();
#else
        DIGICERT_freeDigicert();
#endif
        goto cleanup;
    }
#endif

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    if (0 > (status = gM_IPSEC_init_ptr()))
#else
    if (0 > (status = IPSEC_init()))
#endif
    {
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_IPSEC_flush_ptr();
#else
        IPSEC_flush();
#endif
#if !defined(__DISABLE_DIGICERT_INIT__)
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
        gM_DIGICERT_freeDigicert_ptr();
#else
        DIGICERT_freeDigicert();
#endif
#endif
        goto cleanup;
    }
    phase = 2;
    printk("Mocana IPsec initialized\n");

#ifdef __ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__
    if (0 > (status = ipsec_async_initialize()))
        goto cleanup;
#endif

    if (0 > NF_REGISTER_HOOKS(ipsec_ops, status))
    {
        printk("%s: can't register hooks.\n", __FUNCTION__);
        goto cleanup;
    }
    phase = 3;
    printk("net_filter hooks registered\n");

#ifdef __ENABLE_DIGICERT_IPV6__
    if ( (0 > inet6_add_protocol(&ipsec6_protocol, IPPROTO_ESP)) ||
         (0 > inet6_add_protocol(&ipsec6_protocol, IPPROTO_AH)) )
    {
        printk("%s: can't add protocol.\n", __FUNCTION__);
        status = -1;
        goto cleanup;
    }
    phase = 4;
    printk("ipsec6_protocol added\n");
#endif

    /* PFKEY code */
#ifdef __ENABLE_DIGICERT_PFKEY__
    PFKEY_init();
#endif

cleanup:
    if (0 > status)
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        if (phase == 3)
        {
            inet6_del_protocol(&ipsec6_protocol, IPPROTO_ESP);
            inet6_del_protocol(&ipsec6_protocol, IPPROTO_AH);

            phase--;
        }
#endif

        if (phase == 2)
        {
            NF_UNREGISTER_HOOKS(ipsec_ops);

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_IPSEC_flush_ptr();
#else
            IPSEC_flush();
#endif

#if !defined(__DISABLE_DIGICERT_INIT__)
#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
            gM_DIGICERT_freeDigicert_ptr();
#else
            DIGICERT_freeDigicert();
#endif
#endif

            phase--;
        }

        if (phase == 1)
        {
#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
            device_destroy(mIPsecDevClass, MKDEV(mIPsecDevMajor, 1));
            /*class_unregister(mIPsecDevClass); will be called by class_destroy()!*/
            class_destroy(mIPsecDevClass);
            unregister_chrdev(mIPsecDevMajor, IPSC_NAME);
#else
            unregister_chrdev(IPSC_MAJOR, IPSC_NAME);
#endif
        }
    }
    ERROR_PRINT(("Module loaded - status =%d", status));
    return status;
} /* mss_ipsec_init */

/*------------------------------------------------------------------*/

static void __exit
mss_ipsec_fini(void)
{

#if defined(__ENABLE_DIGICERT_SPLIT_DRIVER__)
    // If we unload first, Unregister callback, we are going away
    if (!module_unloaded)
        gM_register_unload_callback_ptr(NULL);
#endif

    moc_ipsec_cleanup_module();

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
        device_destroy(mIPsecDevClass, MKDEV(mIPsecDevMajor, 1));
        /*class_unregister(mIPsecDevClass); will be called by class_destroy()!*/
        class_destroy(mIPsecDevClass);
        unregister_chrdev(mIPsecDevMajor, IPSC_NAME);
#else
        unregister_chrdev(IPSC_MAJOR, IPSC_NAME);
#endif

        printk("Unloaded moc_ipsec_mod driver\n");
} /* mss_ipsec_fini */

/*------------------------------------------------------------------*/

module_init(mss_ipsec_init);
module_exit(mss_ipsec_fini);
