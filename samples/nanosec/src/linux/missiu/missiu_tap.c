/*
 * missiu_tap.c
 *
 * missiu TAP interface bridge
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 * missiu_tap bridges a TAP interface with a raw socket connected to a
 * particular network interface as shown in the following diagram:
 *
 *
 *                 +-------------------+
 *                 |     missiu_tap    |
 *                 +-------------------+
 *                    ^             ^
 *                    |             |
 *                    |          raw socket
 * user space         |             |
 * ===================================================
 * kernel space       |             |
 *                    |             |
 *                    v             v
 *                +------+      +------+
 *                | tapX |      | ethY |
 *                +------+      +------+
 *                                  |
 *                                  +---------> To Network
 *
 *
 */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/select.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <sys/un.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include "missiu.h"
#include "moptions.h"
#include "mocana.h"
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_FIPS_POWERUP_TEST__)
#include "fips.h"
#endif
#if 0
/* Deprecated since 6.3 */
#include "NNstyle.h"
#include "netcommon.h"
#include "ethernet.h"
#include "ip.h"
#else
#include "debug_console.h"

#define ETHADDRESS_LEN  6       /* Ethernet address length in bytes */
#define ETHID_IP        0x0800
#define ETHID_VLAN      0x8100
#define ETHID_IP6       0x86DD

typedef struct {
    ubyte  aoDstAddr[ETHADDRESS_LEN];
    ubyte  aoSrcAddr[ETHADDRESS_LEN];
    ubyte2 wType;
} ETH_HEADER;

typedef struct {
    ubyte  aoDstAddr[ETHADDRESS_LEN];
    ubyte  aoSrcAddr[ETHADDRESS_LEN];
    ubyte2 wVlanType;
    ubyte2 wVlan;
    ubyte2 wType;
} ETH_VLAN_HEADER;

typedef struct {
#if defined (MOC_LITTLE_ENDIAN)
    ubyte  oIpHdrLen:4,
           oVersion:4;
#elif defined (MOC_BIG_ENDIAN)
    ubyte  oVersion:4,
           oIpHdrLen:4;
#endif
    ubyte  oToS;
    ubyte2 wTotalLen;
    ubyte2 wDatagramId;
    ubyte2 wFragOffset;
    ubyte  oTtL;
    ubyte  oProtocol;
    ubyte2 wCheck;
    ubyte4 dwSrcAddr;
    ubyte4 dwDstAddr;

    /*The options start here. */
} IPHDR;
#endif
#include "ipsec_defs.h"
#include "ipsec_protos.h"
#if 0
/* Deprecated since 6.3 */
#include "tcp.h"
#include "udp.h"
#else
typedef struct {
    ubyte2 wSrcPort;
    ubyte2 wDstPort;
    ubyte4 dwSequencenumber;
    ubyte4 dwAcknowledgenumber;
    ubyte  oTcpHdrLen;
    ubyte  oFlags;
    ubyte2 wWindowsize;
    ubyte2 wChecksum;
    ubyte2 wUrgent;
} TCPHDR;

typedef struct {
    ubyte2 wSrcport;
    ubyte2 wDstport;
    ubyte2 wLen;
    ubyte2 wCheck;
} UDPHDR;
#endif
#include "ipsec_utils.h"
#ifdef __ENABLE_DIGICERT_IPV6__
#include "ipsec6.h"
#endif

/* various file descriptors and global state */
static int tap_fd = -1, raw_fd = -1, cmd_fd = -1, client_fd = -1;
static char cmd_name[IFNAMSIZ + sizeof(CMDFIFO_FMT)];

#define LOG(...) do { \
	printf(__VA_ARGS__); \
    fflush(stdout); \
} while (0)

/* buffer management helper functions */
#define NUM_BUFFERS 4
static int mtu;

struct buffer {
    struct buffer *next; /* buffers are doubly linked */
    struct buffer *prev;
    char *data; /* base pointer */
    char *start; /* start of valid data */
    int size; /* size of valid data pointed to by start */
    int eth_size; /* size of ethernet header */

    /* pointer to the ip header */
    union
    {
        void *generic;
        IPHDR *ip4;
#ifdef __ENABLE_DIGICERT_IPV6__
        struct ip6Hdr *ip6;
#endif
    } iphdr;
    int payload_len; /* length of payload after eth hdr */
    int eth_proto; /* eth type */
    void *ulh; /* pointer to upper layer header */
    unsigned short ulp; /* upper layer protocol */
};

struct buflist {
    struct buffer *head;
    struct buffer *tail;
};

static struct buffer allbufs[NUM_BUFFERS];
static struct buflist freelist;
static struct buflist write2tap;
static struct buflist write2raw;

int buflist_empty(struct buflist *list)
{
    return (list->head == NULL) && (list->tail == NULL);
}

struct buffer *buflist_pop(struct buflist *list)
{
    struct buffer *ret;

    if (buflist_empty(list))
        return NULL;

    if (list->head == NULL || list->tail == NULL)
    {
        LOG("BAD LIST STATE ON POP!!!");
        while(1);
    }

    ret = list->head;
    if (NULL == ret->next)
    {
        list->head = NULL;
        list->tail = NULL;
    }
    else
    {
        list->head = ret->next;
    }
    ret->next = NULL;
    return ret;
}

void buflist_push(struct buflist *list, struct buffer *b)
{
    b->next = NULL;
    if (buflist_empty(list))
    {
        list->tail = b;
        list->head = b;
    }
    else
    {
        if (list->head == NULL || list->tail == NULL)
        {
            LOG("BAD LIST STATE ON PUSH!!!");
            while(1);
        }

        list->tail->next = b;
        list->tail = b;
    }

    if (list->head == NULL || list->tail == NULL)
    {
        LOG("BAD LIST STATE ON PUSH 2!!!");
        while(1);
    }
}

void buffer_reset(struct buffer *b)
{
    b->start = b->data + HEAD_XTRA;
    buflist_push(&freelist, b);
}

int buflist_init(int bufsize)
{
    int i;

    freelist.head = freelist.tail = NULL;
    write2tap.head = write2tap.tail = NULL;
    write2raw.head = write2raw.tail = NULL;

    memset(allbufs, 0, sizeof(allbufs));

    for (i = 0; i < NUM_BUFFERS; i++)
    {
        allbufs[i].data = malloc(bufsize);
        if (!allbufs[i].data)
        {
            LOG("Failed to allocate buffer pool\n");
            return -1;
        }
        /* put it in the free list */
        buffer_reset(&allbufs[i]);
    }
    return 0;
}

void buflist_teardown()
{
    int i;

    for (i = 0; i < NUM_BUFFERS; i++)
        free(allbufs[i].data);
}

int tap_new(char *iface)
{
    struct ifreq ifr;
    int tap_fd = 0, net_fd = 0, err;

    /* Create the tap interface */
    tap_fd = open("/dev/net/tun", O_RDWR|O_NONBLOCK);
    if (tap_fd < 0)
    {
        LOG("Failed to open tap driver: %s\n", strerror(errno));
        goto fail;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    err = ioctl(tap_fd, TUNSETIFF, (void *)&ifr);
    if(err == -1)
    {
        LOG("Failed to create tap device: %s\n", strerror(errno));
        goto fail;
    }

    LOG("Allocated new tap device: %s\n"
        "You may need to manually bring up this interface, e.g.\n"
        "      ip link set dev %s up\n", ifr.ifr_name, ifr.ifr_name);

    /* get the MAC address of the real interface */
    net_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy((char *)ifr.ifr_name, iface, IFNAMSIZ);
    err = ioctl(net_fd, SIOCGIFHWADDR, &ifr);
    if(err == -1)
    {
        LOG("Failed to get real MAC address: %s\n", strerror(errno));
        goto fail;
    }

    /* set MAC address of TAP device to the real MAC address */
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    err = ioctl(tap_fd, SIOCSIFHWADDR, (void *)&ifr);
    if(err == -1)
    {
        LOG("Failed to set MAC address: %s\n", strerror(errno));
        goto fail;
    }

    close(net_fd);
    return tap_fd;

fail:
    if (tap_fd > 0)
        close(tap_fd);
    if (net_fd > 0)
        close(net_fd);
    return -1;
}

static void missiu_cleanup(void)
{
    if (tap_fd != -1)
    {
        close(tap_fd);
        tap_fd = -1;
    }

    if (cmd_fd != -1)
    {
        close(cmd_fd);
        unlink(cmd_name);
        cmd_fd = -1;
    }

    if (client_fd != -1)
    {
        close(client_fd);
        client_fd = -1;
    }

    buflist_teardown();
}

/* buffer for commands */
unsigned char buffer[2048];

static int mmap_arg(struct missiu_shmem *shmem, void **mem)
{
    int fd = -1;

    /* open the shared memory area and mmap it */
    fd = shm_open(shmem->name, O_RDWR, S_IRWXU);
    if (-1 == fd)
    {
        LOG("Failed to open shared memory area: %s\n", strerror(errno));
        goto fail;
    }
    *mem = mmap(NULL, shmem->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == *mem)
    {
        LOG("Failed to map shared memory area", strerror(errno));
        goto fail;
    }
    close(fd);
    return 0;

fail:
    if (-1 != fd)
        close(fd);

    return -1;
}

static int handle_cmd(int fd)
{
    int len;
    int ret = 0;
    struct missiu_tlv *cmdbuf = (struct missiu_tlv *)buffer;
    void *arg;

    ret = recv(fd, buffer, sizeof(buffer), 0);
    if (-1 == ret)
    {
        ret = errno;
        goto done;
    }

    if (ret < sizeof(struct missiu_tlv) || ret != cmdbuf->len)
    {
        LOG("Unexpected command length from client: (recvd %d, expected %d)\n",
            ret, cmdbuf->len);
        ret = -1;
        goto done;
    }

    switch (cmdbuf->type)
    {
    case MISSIU_TAP_STOP:
        LOG("Got stop command.\n");
        missiu_cleanup();
        _exit(0);
        break;

    default:
        LOG("passing command to ipsecadm: %d\n", cmdbuf->type);
        /* The sole argument is the name of a shared memory area where the
         * argument to the ioctl can be found.  We must mmap it.
         */
        ret = mmap_arg((struct missiu_shmem *)cmdbuf->value, &arg);
        if (0 != ret)
            break;

        ret = ipsec_ioctl(cmdbuf->type, (unsigned long)arg);
        if (ret != 0)
            LOG("IOCTL Failed: %d\n", ret);

        munmap(arg, ((struct missiu_shmem *)(cmdbuf->value))->size);

        /* The return of an ioctl is always just a 4-byte code */
        ret = send(fd, &ret, sizeof(ret), 0);
        if (ret != sizeof(ret))
            LOG("failed to send response to client %d\n", ret);

        break;
    }

done:
    return ret;
}

void missiu_signal(int sig)
{
    switch(sig){
    case SIGHUP:
    case SIGTERM:
        missiu_cleanup();
        _exit(0);
        break;
    }
}

int missiu_setup(char *iface)
{
    int ret = 0;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    struct sockaddr_un cmd_addr;
    int bufsize;

    /* Create a tap interface to communicate with the kernel */
    tap_fd = tap_new(iface);
    if (tap_fd == -1)
    {
        ret = -1;
        LOG("failed to create TAP device: %s\n", strerror(errno));
        goto done;
    }

    /* Create a raw socket to communicate with the real network interface */
    raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_fd == -1)
    {
        ret = errno;
        LOG("failed to create raw socket: %s\n", strerror(errno));
        goto done;
    }

    memset(&sll, 0, sizeof(sll));
    memset(&ifr, 0, sizeof(ifr));

    strncpy((char *)ifr.ifr_name, iface, IFNAMSIZ);
    ret = ioctl(raw_fd, SIOCGIFINDEX, &ifr);
    if (ret == -1)
    {
        ret = errno;
        LOG("failed to get iface index: %s\n", strerror(errno));
        goto done;
    }

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    ret = bind(raw_fd, (struct sockaddr *)&sll, sizeof(sll));
    if (ret == -1)
    {
        ret = errno;
        LOG("failed to bind raw socket: %s\n", strerror(errno));
        goto done;
    }

    /* find the MTU and initialize the buffer pool */
    ret = ioctl(raw_fd, SIOCGIFMTU, &ifr);
    mtu = ifr.ifr_mtu;
#ifdef OLD_MISSIU
    bufsize = ifr.ifr_mtu + PAD_XTRA;
#else
    bufsize = 65535 + sizeof(ETH_VLAN_HEADER);
#endif
    ret = buflist_init(bufsize);
    if (ret != 0)
#ifdef OLD_MISSIU
        return ret;
#else
        goto done;
#endif

    LOG("%s: MTU=%d. You may need to adjust the tap device's MTU, e.g.\n"
        "      ifconfig tap0 mtu %d\n",
        iface, mtu, mtu-PAD_XTRA);

    /* create a control socket to communicate with the missiu utility */
    cmd_fd = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
    if (cmd_fd == -1)
    {
        ret = errno;
        LOG("failed to create control socket: %s\n", strerror(errno));
        goto done;
    }

    sprintf(cmd_name, CMDFIFO_FMT, iface);

    /* unlink any stale hangers on.  By now we've grabbed the lock file, so we
     * know we're the sole instance.
     */
    unlink(cmd_name);
    cmd_addr.sun_family = AF_LOCAL;
    strncpy(cmd_addr.sun_path, cmd_name, sizeof(cmd_addr.sun_path));
    ret = bind(cmd_fd, (struct sockaddr *)&cmd_addr, SUN_LEN(&cmd_addr));
    if (ret == -1)
    {
        ret = errno;
        LOG("failed to bind control socket: %s\n", strerror(errno));
        goto done;
    }

    /* Listen for connections. */
    ret = listen(cmd_fd, 5);
    if (ret == -1)
    {
        ret = errno;
        LOG("failed to listen on control socket: %s\n", strerror(errno));
        goto done;
    }

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_FIPS_POWERUP_TEST__)
    ret = FIPS_powerupSelfTest();
    if (0 > ret)
    {
        LOG("powerup test failed: %d\n", ret);
        goto done;
    }
#endif

    /* initialize digicert */
    ret = DIGICERT_initDigicert();
    if (0 > ret)
    {
        LOG("failed to initialize digicert: %d\n", ret);
        goto done;
    }
    ret = IPSEC_init();
    if (0 > ret)
    {
        LOG("failed to initialize ipsec: %d\n", ret);
        goto done;
    }

    return 0;

done:
    missiu_cleanup();
    return ret;
}

static int parse_eth(struct buffer *buf)
{
    ETH_HEADER *eth;
    ETH_VLAN_HEADER *eth_vlan;

    eth = (ETH_HEADER *)buf->start;
    buf->eth_proto = ntohs(eth->wType);
    buf->eth_size = sizeof(ETH_HEADER);
    if (ETHID_VLAN == buf->eth_proto)
    {
        eth_vlan = (ETH_VLAN_HEADER *)buf->start;
        buf->eth_proto = ntohs(eth_vlan->wType);
        buf->eth_size = sizeof(ETH_VLAN_HEADER);
    }

    buf->iphdr.generic = (void *)(buf->start + buf->eth_size);
    buf->payload_len = buf->size - buf->eth_size;
    if (ETHID_IP == buf->eth_proto)
    {
        int totalLen = (int) ntohs(buf->iphdr.ip4->wTotalLen);
        if (buf->payload_len < totalLen)
        {
            DBUG_PRINT(DEBUG_IPSEC,("Bad packet length. Expected %d. Proto=%d",
                                    totalLen,
                                    buf->payload_len,
                                    (int) buf->iphdr.ip4->oProtocol));
            return -1;
        }
        if (buf->payload_len != totalLen)
        {
#if 0
            DBUG_PRINT(DEBUG_IPSEC,("Trim packet buffer. Expected %d. Got %d. Proto=%d.",
                                    totalLen,
                                    buf->payload_len,
                                    (int) buf->iphdr.ip4->oProtocol));
#endif
            buf->payload_len = totalLen;
        }
        buf->ulp = buf->iphdr.ip4->oProtocol;
        buf->ulh = buf->iphdr.generic + buf->iphdr.ip4->oIpHdrLen * 4;
    }
#ifdef __ENABLE_DIGICERT_IPV6__
    else if (ETHID_IP6 == buf->eth_proto)
    {
        int status;
        ubyte2 len, hlen;
        ubyte *dest, *next_hdr;
        intBoolean offset, mf;

        status = GetPktInfo6(buf->iphdr.ip6, (ubyte2)buf->payload_len,
                             &len, &hlen, &next_hdr,
                             &dest, &offset, &mf, 1);
        if (0 != status)
        {
            DBUG_PRINT(DEBUG_IPSEC,("Failed to parse ipv6 packet."));
            return status;
        }
        buf->ulp = *next_hdr;
        buf->payload_len = len;
        buf->ulh = buf->iphdr.generic + hlen;
    }
#endif
    return 0;
}

static int ipsec_apply_psk(struct spd *pxSp, struct buffer *buf)
{
    int status = 0, len;
    ubyte2 rlen, roff = 0;
    unsigned int bufsize;
    ubyte protocol;
    struct ipsecCtx ctx = { 0 };

    /* Move mac header up to top of buffer */
    memmove(buf->data, buf->start, buf->eth_size);
    buf->start = buf->data;

    len = buf->payload_len;

    /* Process output buffer */
    roff = HEAD_XTRA;
#ifdef OLD_MISSIU
    bufsize = mtu + TAIL_XTRA + HEAD_XTRA - buf->eth_size;
#else
    bufsize = 65535 + sizeof(ETH_VLAN_HEADER) - buf->eth_size;
#endif

    ctx.pxSp = pxSp;
    status = IPSEC_applyEx(buf->iphdr.generic - HEAD_XTRA,
                           (ubyte2)((65535 < bufsize) ? 65535 : bufsize),
                           &rlen, &roff, &ctx);
    if (OK > status)
        return status;

    if (HEAD_XTRA < roff)
    {
        /* Yikes!  ipsec overwrote the MAC header. */
        return -1;
    }
    else if (0 != roff)
    {
        /* Close the gap between the mac header and the ip header */
        unsigned int xhdrlen = HEAD_XTRA - roff;
        buf->iphdr.generic = buf->iphdr.generic - xhdrlen;
        memmove(buf->start + roff, buf->start, buf->eth_size);
        buf->start += roff;
    }
    buf->size = rlen + buf->eth_size;

    /* TODO: Do we have to do anything about fragmentation? */

    return status;
}

/* return 0 to let the packet through, non-0 to drop it */
static int missiu_encrypt(struct buffer *buf)
{
    int status;
    ubyte2 rlen, roff = 0;

    int offset = 0, mf = 0;
    ubyte2 dport, sport;
    MOC_IP_ADDRESS_S daddr, saddr;
    struct spd *pxSp = NULL;
    struct sadb *pxSa = NULL;

    status = parse_eth(buf);
    if (0 != status)
        return status;

    if (ETHID_IP != buf->eth_proto
#ifdef __ENABLE_DIGICERT_IPV6__
     && ETHID_IP6 != buf->eth_proto
#endif
        )
    {
        return 0;
    }

    if (4 == buf->iphdr.ip4->oVersion)
    {
        offset = ntohs(buf->iphdr.ip4->wFragOffset);
        mf = offset & IP_MF;
        offset &= IP_OFFMASK;
    }

    /* Get TCP/UDP port numbers, if applicable */
    if ((0 == offset) &&
        ((IPPROTO_TCP == buf->ulp) ||
         (IPPROTO_UDP == buf->ulp) ||
         (IPPROTO_ICMP == buf->ulp)))
    {

        switch (buf->ulp)
        {
        case IPPROTO_TCP:
        {
            TCPHDR *th = (TCPHDR *)(buf->ulh);
            sport = ntohs(th->wSrcPort);
            dport = ntohs(th->wDstPort);
            break;
        }
        case IPPROTO_UDP:
        {
            UDPHDR *uh = (UDPHDR *)(buf->ulh);
            sport = ntohs(uh->wSrcport);
            dport = ntohs(uh->wDstport);
            break;
        }
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
        {
            ubyte *tc = (ubyte *)(buf->ulh);
            sport = ((ubyte2) tc[0] << 8) | (ubyte2) tc[1];
            dport = 0;
            break;
        }
        }
    }
    else
    {
        dport = sport = 0;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (6 == buf->iphdr.ip4->oVersion)
    {
        SET_MOC_IPADDR6(daddr, buf->iphdr.ip6->ip6_daddr);
        SET_MOC_IPADDR6(saddr, buf->iphdr.ip6->ip6_saddr);
    }
    else
#endif
    {
        SET_MOC_IPADDR4(daddr, ntohl(buf->iphdr.ip4->dwDstAddr));
        SET_MOC_IPADDR4(saddr, ntohl(buf->iphdr.ip4->dwSrcAddr));
    }

    status = IPSEC_ready(REF_MOC_IPADDR(daddr), REF_MOC_IPADDR(saddr),
                         buf->ulp, offset, mf, dport, sport, 0, &pxSp, 0, 0);
    if (OK > status)
    {
        /* TODO: Not sure if this case applies to the missiu architecture
         * because we don't distinguish between outbound packets that we
         * generated or that we are forwarding.
         */
        if (0 && (STATUS_IPSEC_BYPASS == status))
        {
            status = IPSEC_ready(REF_MOC_IPADDR(daddr),
                                 REF_MOC_IPADDR(saddr),
                                 buf->ulp, offset, mf,
                                 dport, sport, 1, NULL, 0, 0);
            if (OK == status)
            {
                status = ERR_IPSEC_DROP;
            }
        }

        if (STATUS_IPSEC_BYPASS != status)
        {
            DBUG_PRINT(DEBUG_IPSEC,("IPSEC_ready error: status=%d, len=%d, proto=%d",
                                    status, buf->payload_len, (int) buf->ulp));
        }
    }
    else
    {
        status = ipsec_apply_psk(pxSp, buf);
    }

    if (STATUS_IPSEC_BYPASS == status)
        return 0;
    return status;
}

/* return 0 to let the packet through, non-0 to drop it */
static int missiu_decrypt(struct buffer *buf)
{
    int status;
    ubyte2 rlen, roff = 0;
    struct ipsecCtx ctx = { 0 };

    status = parse_eth(buf);
    if (status != 0)
        return status;

    /* Let anything that isn't IPv4 or IPv6 through */
    if (ETHID_IP != buf->eth_proto
#ifdef __ENABLE_DIGICERT_IPV6__
     && ETHID_IP6 != buf->eth_proto
#endif
        )
    {
        return 0;
    }

    /* decrypt buffer */
    status = IPSEC_permitEx((ubyte *)buf->iphdr.generic, (ubyte2)buf->payload_len,
                            &rlen, &roff, &ctx);

    switch (status)
    {
    case OK:
        if (0 != roff)
        {
            /* take in any space left by the decrypt and move the mac header */
            buf->iphdr.generic = (buf->iphdr.generic + roff);
            memmove(buf->start + roff, buf->start, buf->eth_size);
            buf->start += roff;
        }
        if (rlen < buf->payload_len)
        {
            buf->size -= (buf->payload_len - rlen);
        }

        if (IPSEC_MODE_TUNNEL == ctx.pxSp->oMode)
        {
            /* TODO: how do we handle routing and fragmentation? */
        }
        return 0;

    case STATUS_IPSEC_BYPASS:
        /* Note: Non-first ESP fragments may get here */
        return 0;
        break;

    default:
        DBUG_PRINT(DEBUG_IPSEC,("IPSEC_permit error: status=%d, len=%d",
                                status, buf->payload_len));
        return status;
    }

    return 0;
}

int missiu_tap(void)
{
    int ret = 0, bytes, i, max_fd;
    fd_set rfds, wfds;
    struct timeval tout;
    struct sockaddr_un client_name;
    socklen_t client_len;
    struct buffer *buf;

    while (1)
    {
        FD_ZERO(&rfds);
        FD_SET(tap_fd, &rfds);
        FD_SET(raw_fd, &rfds);
        FD_SET(cmd_fd, &rfds);

        FD_ZERO(&wfds);
        if (!buflist_empty(&write2tap))
            FD_SET(tap_fd, &wfds);
        if (!buflist_empty(&write2raw))
            FD_SET(raw_fd, &wfds);

        tout.tv_sec = 5;
        tout.tv_usec = 0;

        max_fd = tap_fd > raw_fd ? tap_fd : raw_fd;
        max_fd = cmd_fd > max_fd ? cmd_fd : max_fd;

        if (client_fd != -1)
        {
            FD_SET(client_fd, &rfds);
            max_fd = client_fd > max_fd ? client_fd : max_fd;
        }

        ret = select(max_fd + 1, &rfds, &wfds, NULL, &tout);
        if (ret == -1)
        {
            ret = errno;
            LOG("select failed: %s\n", strerror(errno));
            break;
        }

        if (FD_ISSET(tap_fd, &rfds))
        {
            buf = buflist_pop(&freelist);
            if (!buf)
            {
                LOG("Failed to get a buffer.  Dumping packet from tap.\n");
                ret = lseek(tap_fd, 0, SEEK_END);
                if (ret == -1)
                    LOG("BTW, lseek failed: %s\n", strerror(errno));
            }
            else
            {
#ifdef OLD_MISSIU
                bytes = read(tap_fd, buf->start, mtu);
#else
                bytes = read(tap_fd, buf->start, 65535+sizeof(ETH_VLAN_HEADER)-HEAD_XTRA);
#endif
                if (bytes == -1)
                {
                    LOG("failed to read packet: %s\n", strerror(errno));
                    buffer_reset(buf);
                }
                else
                {
                    buf->size = bytes;
                    ret = missiu_encrypt(buf);
                    if (0 == ret)
                        buflist_push(&write2raw, buf);
                    else
                        /* drop the packet */
                        buffer_reset(buf);
                }
            }
        }

        if (FD_ISSET(raw_fd, &wfds))
        {
            buf = buflist_pop(&write2raw);
            if (!buf)
            {
                LOG("Warning: failed to find a packet for raw socket\n");
            } else {

                /* send the packet out the raw socket. */
                ret = write(raw_fd, buf->start, buf->size);
                if (ret == -1) {
                    LOG("failed to send packet: %s\n", strerror(errno));
                }
                buffer_reset(buf);
            }
        }

        if (FD_ISSET(raw_fd, &rfds))
        {
            buf = buflist_pop(&freelist);
            if (!buf)
            {
                LOG("Failed to get a buffer.  Dumping pkt from raw sock.\n");
                ret = lseek(raw_fd, 0, SEEK_END);
                if (ret == -1)
                    LOG("BTW, lseek failed: %s\n", strerror(errno));
            }
            else
            {
#ifdef OLD_MISSIU
                bytes = read(raw_fd, buf->start, mtu);
#else
                bytes = read(raw_fd, buf->start, 65535+sizeof(ETH_VLAN_HEADER)-HEAD_XTRA);
#endif
                if (bytes == -1)
                {
                    LOG("failed to read packet from raw socket: %s\n",
                        strerror(errno));
                    buffer_reset(buf);
                }
                else
                {
                    buf->size = bytes;
                    ret = missiu_decrypt(buf);
                    if (0 == ret)
                        buflist_push(&write2tap, buf);
                    else
                        /* drop the packet */
                        buffer_reset(buf);
                }
            }
        }

        if (FD_ISSET(tap_fd, &wfds))
        {
            buf = buflist_pop(&write2tap);
            if (!buf)
            {
                LOG("Warning: failed to find a packet for tap\n");
            } else {
                /* send the packet up to the kernel */
                ret = write(tap_fd, buf->start, buf->size);
                if (ret == -1) {
                    LOG("failed to pass packet to kernel: %s\n", strerror(errno));
                }
                buffer_reset(buf);
            }

        }

        if (FD_ISSET(cmd_fd, &rfds))
        {
            if (client_fd != -1)
            {
                LOG("failed to accept cmd connection: busy.\n");
            }
            else
            {
                client_len = sizeof(client_name);
                client_fd = accept(cmd_fd, (struct sockaddr *)&client_name,
                                   &client_len);
                if (client_fd == -1)
                {
                    LOG("failed to accept cmd connection: %s\n", strerror(errno));
                }
            }
        }

        if (client_fd != -1 && FD_ISSET(client_fd, &rfds))
        {
            handle_cmd(client_fd);
            close(client_fd);
            client_fd = -1;
            continue;
        }
    }

done:
    missiu_cleanup();
    return ret;
}
