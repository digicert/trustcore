/*
 * ikeadm_example.c
 *
 * Sample implementation of an IKE administrator (server+client)
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


#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EXAMPLES__) || defined(__ENABLE_DIGICERT_BIN_EXAMPLES__)
#ifdef __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__
#ifdef MOCANA_IKEADM_PORT

#include <string.h>
#include <stdio.h>
#ifndef __RTOS_WINCE__
#include <errno.h>
#endif
#include <time.h>

#if defined(__WIN32_RTOS__) || defined(__RTOS_WINCE__)
  #define WIN32_LEAN_AND_MEAN
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0400
  #endif

  #include <windows.h>
  #include <winsock2.h>
#endif

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/mtcp.h"
#include "../common/mudp.h"
#include "../crypto/ca_mgmt.h"
#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_state.h"


/*------------------------------------------------------------------*/

#define ipv4_addr(a,b,c,d) ((a<<24)+(b<<16)+(c<<8)+d)

#ifndef __ENABLE_DIGICERT_IPV6__
#define MOC_UDP_LOOPBACK_ADDR ipv4_addr(127,0,0,1)
#else
static MOC_IP_ADDRESS_S m_addrLoopback =
{
    AF_INET,
    { { ipv4_addr(127,0,0,1) } },
};
#define MOC_UDP_LOOPBACK_ADDR &m_addrLoopback
#endif


#ifdef MOCANA_IKEADM_CLIENT

/*------------------------------------------------------------------*/

ubyte4 gStartTime;

#define mBufSize sizeof(struct ikesa)
static ubyte mBuffer[mBufSize];

static ubyte4 msTimeout = 5000; /* 5 secs */


/*------------------------------------------------------------------*/

static int
MyGetLastError()
{
#if defined(__WIN32_RTOS__)
    return WSAGetLastError();
#else
    return errno;
#endif
}


/*------------------------------------------------------------------*/

static void
print_ip(ubyte4 dwAddr)
{
    printf("%d.%d.%d.%d",
           dwAddr >> 24,
           (dwAddr & 0x00ff0000) >> 16,
           (dwAddr & 0x0000ff00) >> 8,
           (dwAddr & 0x000000ff));
} /* print_ip */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPV6__

static void
print_ip6(const ubyte* ipAddr6)
{
    sbyte4 i, zeros=0;
    for (i=0; i < 16; i += 2)
    {
        if (i && (0 >= zeros)) printf(":");

        if (ipAddr6[i])
        {
            if (0 < zeros) zeros = -1;
            printf("%x%02x", (int) ipAddr6[i], (int) ipAddr6[i+1]);
        }
        else if (ipAddr6[i+1])
        {
            if (0 < zeros) zeros = -1;
            printf("%x", (int) ipAddr6[i+1]);
        }
        else if (i && (0 > zeros) && (14 > i))
        {
            printf("0");
        }
        else if (i && (0 <= zeros))
        {
            if ((0 == zeros++) && (14 > i))
                printf(":");
        }
    }
} /* print_ip6 */

#endif


/*------------------------------------------------------------------*/

static void
PrintIkeSa(IKESA pxSa)
{
    ubyte2 flags = pxSa->flags;
    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)

    ubyte4 timedlt;
    time_t clock;
    sbyte4 i;

    printf("\n");

/* e.g.
 31 IKE cookies={5d7818a17a893204 703b6bd4c210a979} 192.168.3.131
 */
    printf("%3d IKE%s={", pxSa->loc + 1,
           " cookies");
    for (i=0; i < IKE_COOKIE_SIZE; i++)
        printf("%02x", (int) pxSa->poCky_I[i]);
    printf(" ");
    for (i=0; i < IKE_COOKIE_SIZE; i++)
        printf("%02x", (int) pxSa->poCky_R[i]);
    printf("} ");

    TEST_MOC_IPADDR6(peerAddr,
        print_ip6(GET_MOC_IPADDR6(peerAddr));
    )
        print_ip(GET_MOC_IPADDR4(peerAddr));

    if (500 != pxSa->wPeerPort)
        printf("[%d]", (int) pxSa->wPeerPort);

    if ((IKE_NATT_FLAG_US | IKE_NATT_FLAG_PEER) & pxSa->natt_flags)
    {
        printf(" NAT:");
        if (IKE_NATT_FLAG_US & pxSa->natt_flags) printf("us ");
        if (IKE_NATT_FLAG_PEER & pxSa->natt_flags) printf("peer");
    }
    printf("\n");

/* e.g.
    id=<0b757fbf>, created at Thu Apr 05 11:56:45 2007
 */
    time(&clock);
    timedlt = (IS_IKE_SA_AUTHED(pxSa) ? pxSa->dwTimeCreated : pxSa->dwTimeStart);
    clock -= timedlt / 1000;
    printf("    id=<%08lx>, %s at %s", pxSa->dwId,
           (IS_IKE_SA_AUTHED(pxSa) ? "created" : "started"),
           ctime(&clock));

/* e.g.
    initiator mature
 */
    printf("    %s", (IKE_SA_FLAG_INITIATOR & flags) ? "initiator" : "responder");
    if (IKE_SA_FLAG_MATURE & flags) printf(" mature");
    if (IKE_SA_FLAG_REKEYED & flags) printf(" rekeyed");
    printf("\n");

/* e.g.
    usage=176(167)/360 secs, 0.417 kbytes
 */
    if (IS_IKE_SA_AUTHED(pxSa))
    {
        unsigned long timestamp = pxSa->dwTimeCreated - pxSa->dwTimeStamp;
        timestamp = (timestamp && (1000 > timestamp)) ? 1 : (timestamp / 1000);

        printf("    usage=%lu(%lu)",
            (unsigned long)(timedlt / 1000), timestamp);
        if (pxSa->dwExpSecs)
            printf("/%lu", pxSa->dwExpSecs);
        printf(" secs, %lu.%d", pxSa->dwCurKBytes, (pxSa->dwCurBytes * 1000) / 1024);
        if (pxSa->dwExpKBytes)
            printf("/%lu", pxSa->dwExpKBytes);
        printf(" kbytes\n");
    }

} /* PrintIkeSa */


/*------------------------------------------------------------------*/

static void
PrintIke2Sa(IKESA pxSa)
{
    ubyte2 flags = pxSa->flags;
    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)

    ubyte4 timedlt;
    time_t clock;
    sbyte4 i;

    printf("\n");

    printf("%3d IKEv2 spi={", pxSa->loc + 1);
    for (i=0; i < IKE_COOKIE_SIZE; i++)
        printf("%02x", (int) pxSa->poCky_I[i]);
    printf(" ");
    for (i=0; i < IKE_COOKIE_SIZE; i++)
        printf("%02x", (int) pxSa->poCky_R[i]);
    printf("} ");

    TEST_MOC_IPADDR6(peerAddr,
        print_ip6(GET_MOC_IPADDR6(peerAddr));
    )
        print_ip(GET_MOC_IPADDR4(peerAddr));

    if (500 != pxSa->wPeerPort)
        printf("[%d]", (int) pxSa->wPeerPort);

    if ((IKE_NATT_FLAG_US | IKE_NATT_FLAG_PEER) & pxSa->natt_flags)
    {
        printf(" NAT:");
        if (IKE_NATT_FLAG_US & pxSa->natt_flags) printf("us ");
        if (IKE_NATT_FLAG_PEER & pxSa->natt_flags) printf("peer");
    }
    printf("\n");

    time(&clock);
    timedlt = (IS_IKE2_SA_AUTHED(pxSa) ? pxSa->dwTimeCreated : pxSa->dwTimeStart);
    clock -= timedlt / 1000;
    printf("    id=<%08lx>, %s at %s", pxSa->dwId,
           (IS_IKE2_SA_AUTHED(pxSa) ? "created" : "started"),
           ctime(&clock));

    printf("    %s", (IKE_SA_FLAG_INITIATOR & flags) ? "initiator" : "responder");
    if (IKE_SA_FLAG_MATURE & flags) printf(" mature");
    if (IKE_SA_FLAG_REKEYED & flags) printf(" rekeyed");
    printf(" (flags=0x%04x)\n", flags);

    if (IS_IKE2_SA_AUTHED(pxSa))
    {
        unsigned long timestamp = pxSa->dwTimeCreated - pxSa->dwTimeStamp;
        timestamp = (timestamp && (1000 > timestamp)) ? 1 : (timestamp / 1000);

        printf("    usage=%lu(%lu)",
            (unsigned long)(timedlt / 1000), timestamp);
        if (pxSa->dwExpSecs)
            printf("/%lu", pxSa->dwExpSecs);
        printf(" secs, %lu.%d", pxSa->dwCurKBytes, (pxSa->dwCurBytes * 1000) / 1024);
        if (pxSa->dwExpKBytes)
            printf("/%lu", pxSa->dwExpKBytes);
        printf(" kbytes\n");
    }

} /* PrintIke2Sa */


/*------------------------------------------------------------------*/

extern int
main(int argc, char *argv[])
{
    MSTATUS status = OK;
    void *pUdpDescr = NULL;

    ubyte4 dwBufferSize = 1;
    ubyte4 dataLen;

    time_t clock;
    time(&clock);

    printf("ikeadm\n");
    printf("Copyright (c) 2007-2009 Mocana Corp.\n\n");

    /* initialize the system */
    if (OK > (status = RTOS_rtosInit()))
        goto exit;

    if (OK > (status = TCP_INIT()))
        goto exit;

    gStartTime = RTOS_getUpTimeInMS();

    if (OK > (status = UDP_init()))
        goto exit;

    clock -= (gStartTime / 1000);
    printf("System uptime: %lu secs, since %s", gStartTime / 1000, ctime(&clock));

    /* create socket */
    if (OK > (status = UDP_connect(&pUdpDescr,
                                   MOC_UDP_ANY_ADDR, MOC_UDP_ANY_PORT,
                                   MOC_UDP_LOOPBACK_ADDR,
                                   MOCANA_IKEADM_PORT, TRUE)))
    {
        printf("UDP_connect() failed, status = %d (%d)\n", status, MyGetLastError());
        goto exit;
    }

    /* send */
    if (OK > (status = UDP_send(pUdpDescr, mBuffer, dwBufferSize)))
    {
        printf("UDP_send() failed, status = %d (%d)\n", status, MyGetLastError());
        goto exit;
    }

    /* receive */
    for (;;)
    {
        void *ppUdpDescr[1] = { pUdpDescr };

        if (OK > (status = UDP_selReadAvl(ppUdpDescr, 1, msTimeout)))
        {
            if (ERR_UDP_READ_TIMEOUT == status) goto exit;

            printf("UDP_selectAvl() failed, status = %d\n", status);
            goto exit;
        }

        if (NULL == ppUdpDescr[0]) goto exit;

        if (OK > (status = UDP_recv(pUdpDescr, mBuffer, mBufSize, &dataLen)))
        {
            printf("UDP_recv() failed, status = %d (%d)\n", status, MyGetLastError());
            goto exit;
        }

        /* process */
        if (0 == dataLen) goto exit;

        if (sizeof(struct ikesa) == dataLen)
        {
            if (0x80000000 & ((IKESA)mBuffer)->dwId)
                PrintIke2Sa((IKESA)mBuffer);
            else
                PrintIkeSa((IKESA)mBuffer);
        }
        else
        {
            printf("Bad message length: %d\n", dataLen);
        }

    } /* for (;;) */

exit:
    if (NULL != pUdpDescr)
        UDP_unbind(&pUdpDescr);

    return (int)status;
} /* main */


#else


/*------------------------------------------------------------------*/

#include "../common/debug_console.h"


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

extern RTOS_MUTEX g_ikeMtx;


/*------------------------------------------------------------------*/

typedef sbyte4 (*SktProcFunc)(void *pUdpDescr, void *cb,
                              ubyte *poBuffer, ubyte4 dwBufferSize,
                              MOC_IP_ADDRESS dwPeerAddr, ubyte2 wPeerPort);

extern sbyte4 IKE_EXAMPLE_addUdpSkt(void **ppUdpDescr,
                                    void *cb, SktProcFunc funcPtrProc,
                                    MOC_IP_ADDRESS hostAddr, ubyte2 wHostPort);

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
extern int IKE_EXAMPLE_getLastError(void);
#endif


/*------------------------------------------------------------------*/

static sbyte4
IKEADM_EXAMPLE_process(void *pUdpDescr, void *cb,
                       ubyte *poBuffer, ubyte4 dwBufferSize,
                       MOC_IP_ADDRESS dwPeerAddr, ubyte2 wPeerPort)
{
    MSTATUS status = OK;

    IKESA pxSa = NULL;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

    MOC_UNUSED(cb);

    MOC_UNUSED(poBuffer);
    MOC_UNUSED(dwBufferSize);

    IKE_LOCK_R;

    while (NULL != (pxSa = IKE_enumSa(pxSa, 0)))
    {
        struct ikesa sa = *pxSa;

        sa.dwTimeCreated = timenow - sa.dwTimeCreated;
        sa.dwTimeStamp = timenow - sa.dwTimeStamp;
        sa.dwTimeStart = timenow - sa.dwTimeStart;

        if (OK > (status = UDP_sendTo(pUdpDescr, dwPeerAddr, wPeerPort,
                                      (ubyte *)&sa, sizeof(struct ikesa))))
        {
#if defined(__WIN32_RTOS__) || defined (__RTOS_WINCE__)
            if (WSAEWOULDBLOCK == WSAGetLastError())
            {
                RTOS_sleepMS(1000);

                if (OK == (status = UDP_sendTo(pUdpDescr, dwPeerAddr, wPeerPort,
                                               (ubyte *)&sa, sizeof(struct ikesa))))
                    continue;
            }
#endif
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"IKEADM_EXAMPLE: UDP_sendTo() failed, status = ", status);
            DEBUG_ERROR(DEBUG_COMMON,   (sbyte *)"                sendto() returns error ", IKE_EXAMPLE_getLastError());
            break;
        }
    }

    IKE_UNLOCK_R;
    return (sbyte4)status;
} /* IKEADM_EXAMPLE_process */


/*------------------------------------------------------------------*/

extern sbyte4
IKEADM_EXAMPLE_main(void)
{
    sbyte4 status;

    if (0 > (status = IKE_EXAMPLE_addUdpSkt(NULL, NULL,
                                            IKEADM_EXAMPLE_process,
                                            MOC_UDP_LOOPBACK_ADDR,
                                            MOCANA_IKEADM_PORT)))
    {
        goto exit;
    }

exit:
    return status;
} /* IKEADM_EXAMPLE_main */


#endif /* MOCANA_IKEADM_CLIENT */

#endif /* MOCANA_IKEADM_PORT */
#endif /* __ENABLE_DIGICERT_IKE_SERVER_EXAMPLE__ */
#endif /* __ENABLE_DIGICERT_EXAMPLES__ */

