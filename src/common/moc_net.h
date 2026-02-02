/*
 * moc_net.h
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


/*------------------------------------------------------------------*/

#ifndef __MOC_NET_HEADER__
#define __MOC_NET_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__LWIP_STACK__)

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define CLEAR(b)               b.family=AF_INET6; \
                               b.uin.addr6[0]=0; \
                               b.uin.addr6[1]=0; \
                               b.uin.addr6[2]=0; \
                               b.uin.addr6[3]=0; \
                               b.addr=ntohl(0);
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 s6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16



MOC_EXTERN MSTATUS
MIP_CONVERT_ADDR6_NBO(ubyte * pTargetAddr,MOC_IP_ADDRESS moc_addr);

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);




/*copies a MOC_IP_ADDRESS into a SOCKADDR_IN with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_ADDRS(struct SOCKADDR_IN * pTargetAddr, MOC_IP_ADDRESS moc_addr);

/*Populates a MOC_IP_ADDRESS in network byte order*/
MOC_EXTERN MSTATUS
MIP_CONVERT_DIGI_ADDR_NBO(MOC_IP_ADDRESS moc_addr,  struct SOCKADDR_IN * addr );

/*MOC_IP_ADDRESS copy constructor*/
MOC_EXTERN MSTATUS
MIP_COPY_MOCADDRS_CONSTRUCTOR(MOC_IP_ADDRESS pTargetAddr, MOC_IP_ADDRESS moc_addr);

/*MOC_IP_ADDRESS from buffer - hostent h_addr for example */
MOC_EXTERN MSTATUS
MIP_CONVERT_NBO_MADDR_FROM_BUFFER(MOC_IP_ADDRESS moc_addr , char * addr);

/*copies a SOCKADDR_IN to MOC_IP_ADDRESS with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_MOCADDRS(MOC_IP_ADDRESS_S ** pTargetAddr,  struct SOCKADDR_IN * addr);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define CLEAR(b)               b=ntohl(INADDR_ANY);
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4


/*MOC_IP_ADDRESS from buffer - hostent h_addr for example */
MOC_EXTERN MSTATUS
MIP_CONVERT_NBO_MADDR_FROM_BUFFER(MOC_IP_ADDRESS moc_addr , char * addr);

/*Populates a MOC_IP_ADDRESS in network byte order*/
MOC_EXTERN MSTATUS
MIP_CONVERT_DIGI_ADDR_NBO(MOC_IP_ADDRESS moc_addr,  struct SOCKADDR_IN * addr );

/*copies a MOC_IP_ADDRESS into a SOCKADDR_IN with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_ADDRS(struct SOCKADDR_IN * pTargetAddr, MOC_IP_ADDRESS_S * moc_addr);

/*copies a SOCKADDR_IN to MOC_IP_ADDRESS with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_MOCADDRS(MOC_IP_ADDRESS_S * pTargetAddr,  struct SOCKADDR_IN * addr);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR_NBO(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

#endif /* if __ENABLE_DIGICERT_IPV6__*/


#elif defined(__RTOS_OSX__)

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define CLEAR(b)               b.family=AF_INET6; \
                               b.uin.addr6[0]=0; \
                               b.uin.addr6[1]=0; \
                               b.uin.addr6[2]=0; \
                               b.uin.addr6[3]=0; \
                               b.addr=ntohl(0);
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 s6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16



MOC_EXTERN MSTATUS
MIP_CONVERT_ADDR6_NBO(ubyte * pTargetAddr,MOC_IP_ADDRESS moc_addr);

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);




/*copies a MOC_IP_ADDRESS into a SOCKADDR_IN with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_ADDRS(struct SOCKADDR_IN * pTargetAddr, MOC_IP_ADDRESS moc_addr);

/*Populates a MOC_IP_ADDRESS in network byte order*/
MOC_EXTERN MSTATUS
MIP_CONVERT_DIGI_ADDR_NBO(MOC_IP_ADDRESS moc_addr,  struct SOCKADDR_IN * addr );

/*MOC_IP_ADDRESS copy constructor*/
MOC_EXTERN MSTATUS
MIP_COPY_MOCADDRS_CONSTRUCTOR(MOC_IP_ADDRESS pTargetAddr, MOC_IP_ADDRESS moc_addr);

/*MOC_IP_ADDRESS from buffer - hostent h_addr for example */
MOC_EXTERN MSTATUS
MIP_CONVERT_NBO_MADDR_FROM_BUFFER(MOC_IP_ADDRESS moc_addr , char * addr);

/*copies a SOCKADDR_IN to MOC_IP_ADDRESS with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_MOCADDRS(MOC_IP_ADDRESS_S ** pTargetAddr,  struct SOCKADDR_IN * addr);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define CLEAR(b)               b=ntohl(INADDR_ANY);
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4


/*MOC_IP_ADDRESS from buffer - hostent h_addr for example */
MOC_EXTERN MSTATUS
MIP_CONVERT_NBO_MADDR_FROM_BUFFER(MOC_IP_ADDRESS moc_addr , char * addr);

/*Populates a MOC_IP_ADDRESS in network byte order*/
MOC_EXTERN MSTATUS
MIP_CONVERT_DIGI_ADDR_NBO(MOC_IP_ADDRESS moc_addr,  struct SOCKADDR_IN * addr );

/*copies a MOC_IP_ADDRESS into a SOCKADDR_IN with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_ADDRS(struct SOCKADDR_IN * pTargetAddr, MOC_IP_ADDRESS_S * moc_addr);

/*copies a SOCKADDR_IN to MOC_IP_ADDRESS with no transformation */
MOC_EXTERN MSTATUS
MIP_COPY_MOCADDRS(MOC_IP_ADDRESS_S * pTargetAddr,  struct SOCKADDR_IN * addr);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR_NBO(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

#endif /* if __ENABLE_DIGICERT_IPV6__*/


#elif defined(__RTOS_OPENBSD__)

#include <sys/types.h>
#include <sys/socket.h>


#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 s6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#endif /* if __ENABLE_DIGICERT_IPV6__*/

#elif defined(__RTOS_FREEBSD__)

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 s6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#endif /* if __ENABLE_DIGICERT_IPV6__*/


#elif defined(__RTOS_LINUX__)

#if !defined(__RTOS_ZEPHYR__)
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            (a).sin6_addr    = in6addr_any;
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 s6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16
#define SETSCOPE(x)            x.sin6_scope_id = 4;

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS destAddr, ubyte * name);
MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4
#define SETSCOPE(x)

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);
MOC_EXTERN MSTATUS
    DIGI_NET_NAME_TO_IPADDR_NBO(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS_S * destAddr, ubyte * name);


#endif /* if __ENABLE_DIGICERT_IPV6__*/


#elif defined(__RTOS_SOLARIS__)

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 s6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#endif /* if __ENABLE_DIGICERT_IPV6__*/


#elif defined(__RTOS_WIN32__)

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 sin6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16
#define M_ADDR_ANY               in6addr_any
#define SETSCOPE(x,y)          x.sin6_scope_id = y;



MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS destAddr, ubyte * name);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4
#define M_ADDR_ANY               INADDR_ANY
#define SETSCOPE(x,y)

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#endif /* if __ENABLE_DIGICERT_IPV6__*/


#elif defined(__RTOS_CYGWIN__)

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 sin6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

#endif /* if __ENABLE_DIGICERT_IPV6__*/

#elif defined(__RTOS_VXWORKS__)

#include <netinet/in.h>
#include <sys/socket.h>

#ifdef __ENABLE_DIGICERT_IPV6__

#define M_SOCKADDR_IN          sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 sin6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS destAddr, ubyte * name);

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

#else

#define M_SOCKADDR_IN          sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);

MOC_EXTERN MSTATUS
DIGI_NET_NAME_TO_IPADDR(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

MOC_EXTERN MSTATUS
DIGI_NET_IPADDR_TO_NAME(MOC_IP_ADDRESS_S * destAddr, ubyte * name);

#endif /* if __ENABLE_DIGICERT_IPV6__*/


#else /* any other OS */

#ifdef __ENABLE_DIGICERT_IPV6__

#define SOCKADDR_IN            sockaddr_in6

#define M_AF_INET              AF_INET6
#define SETFAMILY(x)           (x).sin6_family         = AF_INET6;
#define SETPORT(y,z)           (y).sin6_port           = htons((z));
#define ZERO_OUT(a)            /* need to implement this ~erik */
#define SIN_ADDR               sin6_addr
#define SIN_PORT               sin6_port
#define S_ADDR                 sin6_addr
#define MOC_AND(b)             &(b)
#define MOC_AND2(b)            (b)
#define MOC_STAR(b)            *(b)
#define MOCADDR(src)           (src).uin.addr6
#define MOCADDRSIZE            16

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);


#else

#define SOCKADDR_IN            sockaddr_in
#define M_AF_INET              AF_INET
#define SETFAMILY(x)           (x).sin_family         = AF_INET;
#define SETPORT(y,z)           (y).sin_port           = htons((z));
#define ZERO_OUT(a)            (a).sin_addr.s_addr    = INADDR_ANY;
#define SIN_ADDR               sin_addr
#define SIN_PORT               sin_port
#define S_ADDR                 s_addr
#define MOC_AND(b)             (b)
#define MOC_AND2(b)            &(b)
#define MOC_STAR(b)            &(b)
#define MOCADDR(c)             (c)
#define MOCADDRSIZE            4

MOC_EXTERN MSTATUS
MIP_CONVERT_NBO(MOC_IP_ADDRESS moc_addr);



#endif /* if __ENABLE_DIGICERT_IPV6__*/

#endif /* OS Type */

#ifdef __cplusplus
}
#endif

#endif /* __MOC_NET_HEADER__ */

