/*
 *  moc_net.c
 *
 * Mocana IP Abstraction Layer
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifdef __RTOS_WIN32__
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
#endif /* __RTOS_WIN32__ */

#include <string.h>

#ifdef __RTOS_VXWORKS__
#include <inetLib.h>
#endif

#include "../common/moptions.h"
#include "../common/moc_net_system.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/moc_net.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"


#ifdef __ENABLE_DIGICERT_PRAGMA_MARK__
#pragma mark osx
#endif

#ifdef __RTOS_OSX__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"

#ifdef __ENABLE_DIGICERT_IPV6__

/*------------------------------------------------------------------*/
/*Populates a SOCKADDR_IN in network byte order*/

extern MSTATUS
MIP_CONVERT_ADDR_NBO(struct SOCKADDR_IN * pTargetAddr,MOC_IP_ADDRESS moc_addr)
{

    MSTATUS status = OK;
    int i;
    ubyte pTempAddr[MOCADDRSIZE];

    if (NULL == moc_addr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }


    DIGI_MEMSET((ubyte *)pTargetAddr->SIN_ADDR.S_ADDR, 0x00, sizeof(struct SOCKADDR_IN));

    /* in order to transform this we need an array of 16 bytes instead of an array of 4 ubyte4 */

    DIGI_MEMCPY(pTempAddr, MOCADDR(*moc_addr), MOCADDRSIZE);

    /* only 32 bits at a time */

    for ( i = 0; i < MOCADDRSIZE*8/32; i++ )
    {
        pTargetAddr->SIN_ADDR.S_ADDR[4*i] = pTempAddr[4*i+3];
        pTargetAddr->SIN_ADDR.S_ADDR[4*i+1] = pTempAddr[4*i+2];
        pTargetAddr->SIN_ADDR.S_ADDR[4*i+2] = pTempAddr[4*i+1];
        pTargetAddr->SIN_ADDR.S_ADDR[4*i+3] = pTempAddr[4*i];
    }

exit:
    return status;

}

/*------------------------------------------------------------------*/
/*Populates a MOC_IP_ADDRESS in network byte order*/

extern MSTATUS
MIP_CONVERT_DIGI_ADDR_NBO(MOC_IP_ADDRESS moc_addr,  struct SOCKADDR_IN * addr )
{
    MSTATUS status = OK;
    int i;
    ubyte pTempAddr[MOCADDRSIZE];
    ubyte pTempAddr2[MOCADDRSIZE];

    if( NULL == addr )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)MOCADDR(*moc_addr), 0x00, MOCADDRSIZE);

    /* in order to transform this we need an array of 16 bytes instead of an array of 4 ubyte4 */

    DIGI_MEMCPY(pTempAddr2, addr->SIN_ADDR.S_ADDR, MOCADDRSIZE);

    /* only 32 bits at a time */

    for ( i = 0; i < MOCADDRSIZE*8/32; i++ )
    {
        pTempAddr[4*i] = pTempAddr2[4*i+3];
        pTempAddr[4*i+1] =  pTempAddr2[4*i+2];
        pTempAddr[4*i+2] = pTempAddr2[4*i+1];
        pTempAddr[4*i+3] = pTempAddr2[4*i];
    }

    DIGI_MEMCPY(MOCADDR(*moc_addr), pTempAddr, MOCADDRSIZE);

exit:
    return status;

}

/*------------------------------------------------------------------*/
/* convert an ipv6 string addr to MOC_IP_ADDRESS  */
extern MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS destAddr, ubyte * name)
{
    MSTATUS status = OK;

    struct addrinfo        Hints, *AddrInfo;
    int                       RetVal;

    memset(&Hints, 0, sizeof (Hints));
    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_DGRAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    RetVal = getaddrinfo((const char *)name, NULL, &Hints, &AddrInfo);
    if (RetVal != 0) {

        status = ERR_INVALID_ARG;

        goto exit;
    }

    memcpy((*destAddr).uin.addr6, &((struct sockaddr_in6 *)(AddrInfo->ai_addr))->sin6_addr, 16);
exit:
    return status;
}

/*------------------------------------------------------------------*/
/*MOC_IP_ADDRESS from buffer - hostent h_addr for example */

extern MSTATUS
MIP_CONVERT_NBO_MADDR_FROM_BUFFER(MOC_IP_ADDRESS moc_addr , char * addr)
{
    MSTATUS status = OK;
    int i;
    ubyte pTempAddr[MOCADDRSIZE];
    ubyte pTempAddr2[MOCADDRSIZE];

    if( NULL == addr )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)MOCADDR(*moc_addr), 0x00, MOCADDRSIZE);

    /* in order to transform this we need an array of 16 bytes instead of an array of 4 ubyte4 */

    DIGI_MEMCPY(pTempAddr2, addr, MOCADDRSIZE);

    /* only 32 bits at a time */

    for ( i = 0; i < MOCADDRSIZE*8/32; i++ )
    {
        pTempAddr[4*i] = pTempAddr2[4*i+3];
        pTempAddr[4*i+1] =  pTempAddr2[4*i+2];
        pTempAddr[4*i+2] = pTempAddr2[4*i+1];
        pTempAddr[4*i+3] = pTempAddr2[4*i];
    }

    DIGI_MEMCPY(MOCADDR(*moc_addr), pTempAddr, MOCADDRSIZE);

exit:
    return status;

}

/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;
#ifndef MOC_BIG_ENDIAN
    int i;
    ubyte pTempAddr[MOCADDRSIZE];
    ubyte pTempAddr2[MOCADDRSIZE];
    if (NULL == moc_addr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTempAddr, 0x00, MOCADDRSIZE );
    /* We need to make a copy in order to work with ubytes instead of ubyte4s */
    DIGI_MEMCPY(pTempAddr2, MOCADDR(*moc_addr), MOCADDRSIZE);


    for ( i = 0; i < MOCADDRSIZE*8/32; i++)
    {
        pTempAddr[4*i] = pTempAddr2[4*i+3];
        pTempAddr[4*i+1] =  pTempAddr2[4*i+2];
        pTempAddr[4*i+2] = pTempAddr2[4*i+1];
        pTempAddr[4*i+3] = pTempAddr2[4*i];

    }

    DIGI_MEMCPY(MOCADDR(*moc_addr), pTempAddr, MOCADDRSIZE) ;

#endif

exit:
    return status;
}

/*------------------------------------------------------------------*/
/*copies a MOC_IP_ADDRESS into a SOCKADDR_IN with no transformation */

extern MSTATUS
MIP_COPY_ADDRS(struct SOCKADDR_IN * pTargetAddr, MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;

    if((NULL == pTargetAddr) || (NULL == moc_addr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    DIGI_MEMCPY(pTargetAddr->SIN_ADDR.S_ADDR,MOCADDR(*moc_addr),MOCADDRSIZE);


exit:
    return status;

}


/*------------------------------------------------------------------*/
/*copies a SOCKADDR_IN to MOC_IP_ADDRESS with no transformation */

extern MSTATUS
MIP_COPY_MOCADDRS(MOC_IP_ADDRESS_S ** pTargetAddr,  struct SOCKADDR_IN * addr)
{
    MSTATUS status = OK;

    if((NULL == pTargetAddr) || (NULL == addr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMCPY(MOCADDR(**pTargetAddr), addr->SIN_ADDR.S_ADDR,MOCADDRSIZE );

exit:
    return status;

}


/*------------------------------------------------------------------*/

extern MSTATUS
MIP_COPY_MOCADDRS_CONSTRUCTOR(MOC_IP_ADDRESS pTargetAddr, MOC_IP_ADDRESS moc_addr)
{

    MSTATUS status = OK;

    if((NULL == pTargetAddr) || (NULL == moc_addr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMCPY(MOCADDR(*pTargetAddr), MOCADDR(*moc_addr), MOCADDRSIZE);
    (*pTargetAddr).family=M_AF_INET;

exit:
    return status;

}

#else


/*------------------------------------------------------------------*/

extern MSTATUS
MIP_CONVERT_ADDR_NBO(ubyte * pTargetAddr,MOC_IP_ADDRESS moc_addr)
{
    *pTargetAddr=htonl(moc_addr);
    return OK;
}


/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS * moc_addr)
{
    MSTATUS status = OK;
    MOC_IP_ADDRESS temp = htonl(*moc_addr);
    *moc_addr = temp;


    return status;
}

/*------------------------------------------------------------------*/
/*MOC_IP_ADDRESS from buffer - hostent h_addr for example */

extern MSTATUS
MIP_CONVERT_NBO_MADDR_FROM_BUFFER(MOC_IP_ADDRESS moc_addr , char * addr)
{
    moc_addr = ntohl(*((MOC_IP_ADDRESS *)addr));
    return OK;
}

/*Populates a MOC_IP_ADDRESS in network byte order*/
extern MSTATUS
MIP_CONVERT_DIGI_ADDR_NBO(MOC_IP_ADDRESS moc_addr,  struct SOCKADDR_IN * addr )
{
    moc_addr = htonl((*addr).SIN_ADDR.S_ADDR);
    return OK;
}


/*------------------------------------------------------------------*/
/*copies a MOC_IP_ADDRESS into a SOCKADDR_IN with no transformation */

extern MSTATUS
MIP_COPY_ADDRS(struct SOCKADDR_IN * pTargetAddr, MOC_IP_ADDRESS_S * moc_addr)
{
    MSTATUS status = OK;

    if((NULL == pTargetAddr) || (NULL == moc_addr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    DIGI_MEMCPY(&(*pTargetAddr).SIN_ADDR.S_ADDR,moc_addr,MOCADDRSIZE);


exit:
    return status;

}


/*------------------------------------------------------------------*/
/*copies a SOCKADDR_IN to MOC_IP_ADDRESS with no transformation */

extern MSTATUS
MIP_COPY_MOCADDRS(MOC_IP_ADDRESS_S * pTargetAddr,  struct SOCKADDR_IN * addr)
{
    MSTATUS status = OK;

    *pTargetAddr=addr->SIN_ADDR.S_ADDR;


    return status;

}
/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;

    inet_aton((const char*)name, &iar);
    *destAddr = iar.s_addr;

   return status;

}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR_NBO(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;

    inet_aton((const char*) name, &iar);
    *destAddr = htonl(iar.s_addr);

   return status;

}
/*------------------------------------------------------------------*/


#endif /* __ENABLE_DIGICERT_IPV6__ */

#endif /* __RTOS_OSX__ */


#ifdef __ENABLE_DIGICERT_PRAGMA_MARK__
#pragma mark linux
#endif
#if defined(__RTOS_LINUX__) || defined(__RTOS_CYGWIN__)


#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/moc_net.h"
#include "../common/mstdlib.h"
#include <string.h>  /* for strcpy() */

#if defined(__RTOS_ZEPHYR__)
#include <zephyr/net/net_ip.h>
#include <zephyr/posix/arpa/inet.h>
#elif !defined(__LWIP_STACK__)
/* When LWIP is compiled in, these headers cause duplicate definitions. */
#include <netinet/in.h>
#include <netdb.h>
#endif


#ifdef __ENABLE_DIGICERT_IPV6__
/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;

#ifndef MOC_BIG_ENDIAN
    int i;
    ubyte pTempAddr[MOCADDRSIZE];
    ubyte pTempAddr2[MOCADDRSIZE];
    if (NULL == moc_addr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTempAddr, 0x00, MOCADDRSIZE );
    /* We need to make a copy in order to work with ubytes instead of ubyte4s */
    DIGI_MEMCPY(pTempAddr2, MOCADDR(*moc_addr), MOCADDRSIZE);


    for ( i = 0; i < MOCADDRSIZE*8/32; i++)
    {
        pTempAddr[4*i] = pTempAddr2[4*i+3];
        pTempAddr[4*i+1] =  pTempAddr2[4*i+2];
        pTempAddr[4*i+2] = pTempAddr2[4*i+1];
        pTempAddr[4*i+3] = pTempAddr2[4*i];

    }

    DIGI_MEMCPY(MOCADDR(*moc_addr), pTempAddr, MOCADDRSIZE) ;

#endif

exit:
    return status;
}

/* convert an ipv6 string addr to MOC_IP_ADDRESS  */
extern MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS destAddr, ubyte * name)
{
    MSTATUS status = OK;

    struct addrinfo        Hints, *AddrInfo;
    int                       RetVal;

    memset(&Hints, 0, sizeof (Hints));
    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_DGRAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    RetVal = getaddrinfo((const char *)name, NULL, &Hints, &AddrInfo);
    if (RetVal != 0) {

        status = ERR_INVALID_ARG;

        goto exit;
    }

    if (AddrInfo && AddrInfo->ai_addr)
        memcpy((*destAddr).uin.addr6, &((struct sockaddr_in6 *)(AddrInfo->ai_addr))->sin6_addr, 16);

    if (AddrInfo)
        freeaddrinfo(AddrInfo);

exit:
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    MSTATUS status = -1;

    return status;

}

#else /* __ENABLE_DIGICERT_IPV6__ */

/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;
    MOC_IP_ADDRESS temp = htonl(moc_addr);
    moc_addr = temp;

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR_NBO(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;

    /* inet_pton() returns 0 if ip address in name is malformed */
    if (0 == inet_pton(AF_INET, (const char *)name, &iar))
        status = ERR_GENERAL;
    else
        *destAddr = htonl(iar.s_addr);

    return status;

}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;

    /* inet_pton() returns 0 if ip address in name is malformed */
    if (0 == inet_pton(AF_INET, (const char *)name, &iar))
        status = ERR_GENERAL;
    else
        *destAddr = iar.s_addr;

    return status;

}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;
    char *sDestAddr = NULL;

    if (NULL == name || NULL == destAddr)
        return ERR_NULL_POINTER;

    iar.s_addr = htonl(*destAddr);
    sDestAddr = inet_ntoa(iar);

    if (NULL != sDestAddr)
    {
        status = OK;
        strcpy( (char *)name, sDestAddr );
    }
    else
    {
        status = ERR_INVALID_ARG;
        strcpy( (char *)name, "" );
    }

    return status;

}

/*------------------------------------------------------------------*/


#endif /* if __ENABLE_DIGICERT_IPV6__ */

#endif /* __RTOS_LINUX__ */

#ifdef __ENABLE_DIGICERT_PRAGMA_MARK__
#pragma mark freebsd
#endif
#ifdef __RTOS_FREEBSD__

#ifdef __ENABLE_DIGICERT_IPV6__
/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;

#ifndef MOC_BIG_ENDIAN
    int i;
    ubyte pTempAddr[MOCADDRSIZE];
    ubyte pTempAddr2[MOCADDRSIZE];
    if (NULL == moc_addr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTempAddr, 0x00, MOCADDRSIZE );
    /* We need to make a copy in order to work with ubytes instead of ubyte4s */
    DIGI_MEMCPY(pTempAddr2, MOCADDR(*moc_addr), MOCADDRSIZE);


    for ( i = 0; i < MOCADDRSIZE*8/32; i++)
    {
        pTempAddr[4*i] = pTempAddr2[4*i+3];
        pTempAddr[4*i+1] =  pTempAddr2[4*i+2];
        pTempAddr[4*i+2] = pTempAddr2[4*i+1];
        pTempAddr[4*i+3] = pTempAddr2[4*i];

    }

    DIGI_MEMCPY(MOCADDR(*moc_addr), pTempAddr, MOCADDRSIZE) ;

#endif

exit:
    return status;
}

#else /* __ENABLE_DIGICERT_IPV6__ */

/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;
    MOC_IP_ADDRESS temp = htonl(moc_addr);
    moc_addr = temp;


    return status;
}


#endif /* if __ENABLE_DIGICERT_IPV6__ */

#endif /* __RTOS_FREEBSD__ */

#ifdef __ENABLE_DIGICERT_PRAGMA_MARK__
#pragma mark win32
#endif
#ifdef __RTOS_WIN32__

#ifdef __ENABLE_DIGICERT_IPV6__

/* convert an ipv6 string addr to MOC_IP_ADDRESS  */
extern MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS destAddr, ubyte * name)
{
    MSTATUS status = OK;

    struct addrinfo    Hints, *AddrInfo;
    int                RetVal;

    memset(&Hints, 0, sizeof (Hints));
    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_DGRAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    RetVal = getaddrinfo((const char *)name, NULL, &Hints, &AddrInfo);
    if (RetVal != 0) {

        WSACleanup();

        goto exit;
    }

    memcpy((*destAddr).uin.addr6, &((struct sockaddr_in6 *)(AddrInfo->ai_addr))->sin6_addr, 16);
exit:
    return status;
}

/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;

#ifndef MOC_BIG_ENDIAN
    int i;
    ubyte pTempAddr[MOCADDRSIZE];
    ubyte pTempAddr2[MOCADDRSIZE];
    if (NULL == moc_addr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTempAddr, 0x00, MOCADDRSIZE );
    /* We need to make a copy in order to work with ubytes instead of ubyte4s */
    DIGI_MEMCPY(pTempAddr2, MOCADDR(*moc_addr), MOCADDRSIZE);


    for ( i = 0; i < MOCADDRSIZE*8/32; i++)
    {
        pTempAddr[4*i] = pTempAddr2[4*i+3];
        pTempAddr[4*i+1] =  pTempAddr2[4*i+2];
        pTempAddr[4*i+2] = pTempAddr2[4*i+1];
        pTempAddr[4*i+3] = pTempAddr2[4*i];

    }

    DIGI_MEMCPY(MOCADDR(*moc_addr), pTempAddr, MOCADDRSIZE) ;

#endif

exit:
    return status;
}

#else /* __ENABLE_DIGICERT_IPV6__ */

/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;
    MOC_IP_ADDRESS temp = htonl(moc_addr);
    moc_addr = temp;


    return status;
}

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR_NBO(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;
    iar.s_addr = inet_addr(name);
    /* inet_aton(name, &iar); */
    *destAddr = htonl(iar.s_addr);

    return status;
}

#endif /* if __ENABLE_DIGICERT_IPV6__ */

#endif /* __RTOS_WIN32__ */


/*------------------------------------------------------------------*/

#ifdef __RTOS_VXWORKS__

#ifdef __ENABLE_DIGICERT_IPV6__
#include <netdb.h>

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;

#ifndef MOC_BIG_ENDIAN
    int i;
    ubyte pTempAddr[MOCADDRSIZE];
    ubyte pTempAddr2[MOCADDRSIZE];
    if (NULL == moc_addr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTempAddr, 0x00, MOCADDRSIZE );
    /* We need to make a copy in order to work with ubytes instead of ubyte4s */
    DIGI_MEMCPY(pTempAddr2, MOCADDR(*moc_addr), MOCADDRSIZE);


    for ( i = 0; i < MOCADDRSIZE*8/32; i++)
    {
        pTempAddr[4*i] = pTempAddr2[4*i+3];
        pTempAddr[4*i+1] =  pTempAddr2[4*i+2];
        pTempAddr[4*i+2] = pTempAddr2[4*i+1];
        pTempAddr[4*i+3] = pTempAddr2[4*i];

    }

    DIGI_MEMCPY(MOCADDR(*moc_addr), pTempAddr, MOCADDRSIZE) ;

#endif

exit:
    return status;
}


/*------------------------------------------------------------------*/


MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS destAddr, ubyte * name)
{
    MSTATUS status = OK;

    struct addrinfo    Hints, *AddrInfo;
    int                RetVal;

    memset(&Hints, 0, sizeof (Hints));
    Hints.ai_family = M_AF_INET;
    Hints.ai_socktype = SOCK_DGRAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    RetVal = getaddrinfo((const char *)name, NULL, &Hints, &AddrInfo);
    if (RetVal != 0) {
        goto exit;
    }

    memcpy((*destAddr).uin.addr6, &((struct sockaddr_in6 *)(AddrInfo->ai_addr))->sin6_addr, 16);
exit:
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = -1;

exit:
    return status;

}

#else /* __ENABLE_DIGICERT_IPV6__ */

/*------------------------------------------------------------------*/
/* reflexively covert a MOC_IP_ADDRESS to network byte order */

extern MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr)
{
    MSTATUS status = OK;
    MOC_IP_ADDRESS temp = htonl(moc_addr);
    moc_addr = temp;


    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;

    /* inet_aton() returns 0 if ip address in name is malformed */
    if (0 == inet_aton((char *)name, &iar))
        status = ERR_GENERAL;
    else
        *destAddr = iar.s_addr;

    return status;

}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;

    iar.s_addr = htonl(*destAddr);
    strcpy( (char *)name, inet_ntoa(iar) );

    return status;

}



#endif

#endif /*__RTOS_VXWORKS__*/

/*------------------------------------------------------------------*/

#ifdef __RTOS_OPENBSD__
#include <netinet/in.h>

#ifdef __ENABLE_DIGICERT_IPV6__

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = -1;

exit:
    return status;

}

#else /* __ENABLE_DIGICERT_IPV6__ */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;
    MSTATUS status = OK;

    iar.s_addr = htonl(*destAddr);
    strcpy( name, inet_ntoa(iar) );

    return status;

}

#endif

#endif /* __RTOS_OPENBSD__ */
