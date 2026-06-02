/**
 * @file  pfkey_utils.c
 * @brief PF_KEY Kernel Interface - Utility Functions
 *
 * @since 3.2
 * @version 3.2 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_PFKEY__
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
 *
 */

/* Doc Note: These functions are for Mocana internal use only and are not to be documented.
*/
#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_PFKEY__)

#if defined(__WIN32_RTOS__)
#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#elif defined(__LINUX_RTOS__) || defined (__VXWORKS_RTOS__) || defined(__OPENBSD_RTOS__) || defined(__QNX_RTOS__) || defined(__SOLARIS_RTOS__) || defined(__CYGWIN_RTOS__)
#if !defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)
#include <sys/types.h>
#include <sys/socket.h>
#endif

#if defined(__OPENBSD_RTOS__) || defined(__SOLARIS_RTOS__) || defined(__VXWORKS_RTOS__)
#include <netinet/in.h>
#elif defined(__LINUX_RTOS__)
#include <linux/in.h>
#include <linux/in6.h>
#elif defined(__CYGWIN_RTOS__)
#include <cygwin/in.h>
#endif

#endif

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/int64.h"
#include "../crypto/crypto.h"

#include "../pfkey/pfkey.h"
#include "../pfkey/pfkeyv2_common.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"

#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_childsa.h"


/*------------------------------------------------------------------*/

/* useful macro for making sure we don't integer overflow from an attack */
#define ADJUST_LEN_MACRO(X)       { if (len < (X)) { status = ERR_PFKEY_PARSE_BAD_LENGTH; goto exit; } len -= (X); }


/*------------------------------------------------------------------*/

extern MSTATUS
pfkey_buildBase(ubyte4 seqNo, ubyte4 pid, ubyte proto, ubyte msgType,
                ubyte errNo, ubyte2 msgLen, struct sadb_msg *pBase)
{
    MSTATUS status = OK;

    pBase->sadb_msg_version = PF_KEY_V2;
    pBase->sadb_msg_type = msgType;
    pBase->sadb_msg_errno = errNo;

    if (IPPROTO_AH == proto)
    {
        pBase->sadb_msg_satype = SADB_SATYPE_AH;
    }
    else if (IPPROTO_ESP == proto)
    {
        pBase->sadb_msg_satype = SADB_SATYPE_ESP;
    }
    else
    {
        status = ERR_PFKEY_INVALID_PARAMETER;
        goto exit;
    }

    pBase->sadb_msg_len = msgLen / 8;
    pBase->sadb_msg_seq = seqNo;
    pBase->sadb_msg_pid = pid;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* flag = 1 indicates only spi field is valid */
extern MSTATUS
pfkey_buildAssocExtension(ubyte4 dwSpi,
                          ubyte authAlgo, ubyte encrAlgo, ubyte aeadTag,
                          struct sadb_sa *pSa, ubyte state, ubyte flag)
{
    MSTATUS status = OK;

    pSa->sadb_sa_len = sizeof(struct sadb_sa)/8;
    pSa->sadb_sa_exttype = SADB_EXT_SA;

    /* double check if this is needed */
    DIGI_HTONL((ubyte *)&pSa->sadb_sa_spi, dwSpi);
    pSa->sadb_sa_state = state;

    if (flag) goto exit;

    if (0 == authAlgo)
    {
        pSa->sadb_sa_auth = SADB_AALG_NONE;
    }
    else
    {
        CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(0, 0, 0, authAlgo);
        if (NULL == pAuthAlgo)
        {
            DEBUG_PRINTNL(DEBUG_PFKEY_MESSAGE, (sbyte *)"Unknown auth algo\n");
            status = ERR_PFKEY_INVALID_PARAMETER;
            goto exit;
        }
        else
        {
            pSa->sadb_sa_auth = pAuthAlgo->oTfmId;
        }
    }

    if (0 == encrAlgo)
    {
        pSa->sadb_sa_encrypt = SADB_EALG_NONE;
    }
    else
    {
        CHILDSA_encrInfo *pEncrAlgo = CHILDSA_findAeadAlgo(0, 0, encrAlgo, aeadTag, 0, NULL);
        if (NULL == pEncrAlgo)
        {
            DEBUG_PRINTNL(DEBUG_PFKEY_MESSAGE, (sbyte *)"Unknown encrypt algo\n");
            status = ERR_PFKEY_INVALID_PARAMETER;
            goto exit;
        }
        else
        {
            pSa->sadb_sa_encrypt = pEncrAlgo->oTfmId;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
pfkey_parseAddressExtension(struct sadb_address *pExt,
                            MOC_IP_ADDRESS_S *pAddr,
                            ubyte *pProto, ubyte2 *pPort)
{
    MSTATUS status = OK;
    struct sockaddr_in *pSockAddr = (struct sockaddr_in *)(pExt + 1);

    if (AF_INET == pSockAddr->sin_family)
    {
        SET_MOC_IPADDR4(*pAddr, DIGI_NTOHL((ubyte *) &pSockAddr->sin_addr.s_addr));
        if (pPort) *pPort = DIGI_NTOHS((ubyte *) &pSockAddr->sin_port);
    }
    else
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        struct sockaddr_in6 *pSockAddr6 = (struct sockaddr_in6 *)pSockAddr;

        if (AF_INET6 == pSockAddr6->sin6_family)
        {
            if (pExt->sadb_address_len <
                (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                   sizeof(struct sockaddr_in6)), 8)))
            {
                status = ERR_PFKEY_PARSE_BAD_LENGTH;
                goto exit;
            }
            SET_MOC_IPADDR6(*pAddr, pSockAddr6->sin6_addr.s6_addr);
            if (pPort) *pPort = DIGI_NTOHS((ubyte *) &pSockAddr6->sin6_port);
        }
        else
#endif
        {
            status = ERR_PFKEY_PROTOCOL_TYPE;
            goto exit;
        }
    }

    if (pProto) *pProto = pExt->sadb_address_proto;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
pfkey_buildAddressExtension(ubyte2 extType, MOC_IP_ADDRESS addr,
                            struct sadb_address *pAddr)
{
    MSTATUS status = OK;

    pAddr->sadb_address_exttype = extType;

    TEST_MOC_IPADDR6(addr,
    {
        struct sockaddr_in6* pSockAddr6;

        pAddr->sadb_address_len = (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                   sizeof(struct sockaddr_in6)), 8));
        pAddr->sadb_address_prefixlen = 128;

        pSockAddr6 = (struct sockaddr_in6 *)(pAddr + 1);
        pSockAddr6->sin6_family = AF_INET6;
        DIGI_MEMCPY((ubyte *) pSockAddr6->sin6_addr.s6_addr, GET_MOC_IPADDR6(addr), 16);
    })
    {
        struct sockaddr_in* pSockAddr;

        pAddr->sadb_address_len = (PFKEY_DIVROUNDUP((sizeof(struct sadb_address) +
                                   sizeof(struct sockaddr_in)), 8));
        pAddr->sadb_address_prefixlen = 32;

        pSockAddr = (struct sockaddr_in *)(pAddr + 1);
        pSockAddr->sin_family = AF_INET;
        DIGI_HTONL((ubyte *) &pSockAddr->sin_addr.s_addr, GET_MOC_IPADDR4(addr));
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
pfkey_buildKeyExtension(struct sadb_key *pKey, ubyte2 extType, ubyte *keyData, ubyte2 keyDataLen)
{
    MSTATUS status = OK;

    pKey->sadb_key_len = (sizeof(struct sadb_key) +
                      (PFKEY_DIVROUNDUP(keyDataLen, 64) * PFKEY_ALIGN))/PFKEY_ALIGN;

    pKey->sadb_key_exttype = extType;
    pKey->sadb_key_bits = keyDataLen;

    if (keyDataLen)
    status = DIGI_MEMCPY((pKey + 1), keyData, PFKEY_DIVROUNDUP(keyDataLen, 8));

    return status;
}


#endif /* __ENABLE_DIGICERT_PFKEY__ */

