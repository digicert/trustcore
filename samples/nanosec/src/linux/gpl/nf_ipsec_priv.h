/*
 * nf_ipsec_priv.h
 *
 * Linux IPsec kernel module private header
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

#ifndef __NF_IPSEC_PRIV_H__
#define __NF_IPSEC_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
extern int  ipsec_async_initialize(void);
extern void ipsec_async_cleanup(void);

struct sk_buff;
extern void ipsec_async_piggyback_flow(struct sk_buff *skb,
                                       void *sp, void *sa);
#endif

#include "nf_ipsec.h"

/*------------------------------------------------------------------*/
#define SKB_PUSHABLE(a) (skb_headroom(a) >= (((a)->mac_len ? (a)->mac_len : 16) + HEAD_XTRA))

#define CHECK_HEAD_ROOM


/*------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
static inline unsigned char *skb_end_pointer(const struct sk_buff *skb)
{
    return skb->end;
}

static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
    return skb->tail;
}

static inline void skb_set_transport_header(struct sk_buff *skb, const int offset)
{
    skb->h.raw = skb->data + offset;
}

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
   return skb->nh.raw;
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
    skb->nh.raw = skb->data;
}

static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
    return skb->mac.raw;
}

static inline int skb_mac_header_was_set(const struct sk_buff *skb)
{
    return (NULL != skb->mac.raw);
}

#ifdef __ENABLE_DIGICERT_IPV6__
static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
    return skb->h.raw;
}

static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
    return (struct ipv6hdr *)skb_network_header(skb);
}
#endif

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)) */

#define skb_ip_header(s) (struct iphdr *) skb_network_header(s)

#if 0 //( (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)) || (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,14)) )
/* This code is not available on 2.6.18+ tree */
static inline u32
dst_path_metric(const struct dst_entry *dst, int metric)
{
#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)) )
    return (DST_METRICS_PTR(dst->path))[metric-1];
#elif ( (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,38)) )
    return dst->path->_metrics[metric-1];
#else
    return dst->path->metrics[metric-1];
#endif
}

static inline u32
dst_pmtu(const struct dst_entry *dst)
{
    u32 mtu = dst_path_metric(dst, RTAX_MTU);
    /* Yes, _exactly_. This is paranoia. */
    barrier();
    return mtu;
}
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,30))
static inline struct dst_entry *
skb_dst(const struct sk_buff *skb)
{
    return (struct dst_entry *)skb->dst;
}

static inline struct rtable *
skb_rtable(const struct sk_buff *skb)
{
    return (struct rtable *)skb_dst(skb);
}

static inline void
skb_dst_drop(struct sk_buff *skb)
{
    dst_release(skb->dst);
    skb->dst = NULL;
}
#endif

#ifdef __cplusplus
}
#endif

#endif                                  /* __NF_IPSEC_PRIV_H__ */

