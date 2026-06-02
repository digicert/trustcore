/**
 * @file  script.c
 * @brief NanoSec IPsec policy script parser implementation.
 *
 * @details    This file contains IPsec policy script parsing implementation.
 * @flags      Compilation flags required:
 *     To enable this file's functions, at least one of the following flags must be
 *     defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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

#include <string.h>
#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) || defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/debug_console.h"
#include "../common/dynarray.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/spd.h"
#include "../ipsec/script.h"
#include "if_mapping.h"
#ifdef __ENABLE_DIGICERT_IPV6__
#include <stdint.h>
#endif


typedef struct Token
{
    const sbyte* m_str;
    sbyte4 m_len;
    sbyte4 m_extra;
} Token;

/* symbolic constants for the pattern/properties/command tokens  */
enum {
    kSAddr,
    kSPort,
    kDAddr,
    kDPort,
    kUlp,
    kDir,
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    kIfId,
#endif
    kAuthAlg = 0, /* don' t change this, also used as index in array -> start at 0 */
    kEncrAlg,
    kEncrAuthAlg,
    kTunnelSrc,
    kTunnelDst,
    kKeyLength,
    kAeadTag,
    kSaAttr,
    kExpSecs,
    kExpBytes,
    kTunnelRAddr,
    kTunnelLAddr,

    kRAddr,
    kRAddrList,
    kRPort,
    kLAddr,
    kLAddrEx,
    kLAddrList,
    kLPort,
    kPortList,
    kLPortList,

    kAdd,
    kFlush,
    kSpdFlush,
};

/* possible pattern names */
static Token gPatternTokens[] =
{
    {(const sbyte*)"saddr", 5, kSAddr },
    {(const sbyte*)"sport", 5, kSPort },
    {(const sbyte*)"daddr", 5, kDAddr },
    {(const sbyte*)"dport", 5, kDPort },

    {(const sbyte*)"ulp", 3, kUlp },
    {(const sbyte*)"dir", 3, kDir },
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    {(const sbyte*)"ifid",  4, kIfId  },
#endif
    {(const sbyte*)"raddr", 5, kRAddr },
    {(const sbyte*)"raddr_list", 10, kRAddrList },
    {(const sbyte*)"rport", 5, kRPort },
    {(const sbyte*)"laddr", 5, kLAddr },
    {(const sbyte*)"laddr_ex", 8, kLAddrEx },
    {(const sbyte*)"laddr_list", 10, kLAddrList },
    {(const sbyte*)"lport", 5, kLPort },
    {(const sbyte*)"lport_list", 10, kLPortList },
    {(const sbyte*)"port_list", 9, kPortList }

};

ipsec_portlist m_ipsec_portlist[MAX_NUM_ADDRESS_TRANSLATION]={0};

/* possible host -> customize to prevent DNS lookup*/
static Token gHostTokens[] =
{
    {(const sbyte*)"localhost", 9, ((((ubyte4)127) << 24) + 1)}
};

/* possible ports */
static Token gPortTokens[] =
{
    {(const sbyte*)"http", 4, 80 },
    {(const sbyte*)"telnet", 6, 23 }
    /* add others as needed specifying the port number as m_extra */
};

/* possible upper layer protocol */
static Token gProtocolTokens[] =
{
    {(const sbyte*)"icmp",      4, IPPROTO_ICMP     },
    {(const sbyte*)"ipip",      4, IPPROTO_IPIP     },
    {(const sbyte*)"ipv6",      4, IPPROTO_IPV6     },
    {(const sbyte*)"tcp",       3, IPPROTO_TCP      },
    {(const sbyte*)"udp",       3, IPPROTO_UDP      },
    {(const sbyte*)"esp",       3, IPPROTO_ESP      },
    {(const sbyte*)"ah",        2, IPPROTO_AH       },
    {(const sbyte*)"icmp6",     5, IPPROTO_ICMPV6   },
    {(const sbyte*)"ipv6-icmp", 9, IPPROTO_ICMPV6   }
    /* add others as needed */
};

/* possible directions */
static Token gDirectionTokens[] =
{
    {(const sbyte*)"out",       3, IPSEC_DIR_OUTBOUND },
    {(const sbyte*)"in",        2, IPSEC_DIR_INBOUND },
    {(const sbyte*)"mirrored",  8, IPSEC_DIR_MIRRORED },
    {(const sbyte*)"out_mirrored", 12, (IPSEC_DIR_OUTBOUND | IPSEC_DIR_MIRRORED) },
    {(const sbyte*)"in_mirrored", 11, (IPSEC_DIR_INBOUND | IPSEC_DIR_MIRRORED) }
};

/* possible actions */
#define IPSEC_ACTION_IPSEC 5 /* temporary (used in this file only) */

static Token gActionTokens[] =
{
    {(const sbyte*)"ipsec",     5, IPSEC_ACTION_IPSEC },

    {(const sbyte*)"apply",     5, IPSEC_ACTION_APPLY },
    {(const sbyte*)"permit",    6, IPSEC_ACTION_PERMIT },
    {(const sbyte*)"bypass",    6, IPSEC_ACTION_BYPASS },
    {(const sbyte*)"drop",      4, IPSEC_ACTION_DROP }
};

/* possible properties names */
static Token gPropertyTokens[] =
{
    {(const sbyte*)"auth_algs", 9, kAuthAlg },
    {(const sbyte*)"encr_algs", 9, kEncrAlg },
    {(const sbyte*)"encr_auth_algs", 14, kEncrAuthAlg },

    {(const sbyte*)"tsrc",      4, kTunnelSrc },
    {(const sbyte*)"tdst",      4, kTunnelDst },

    {(const sbyte*)"keylength", 9, kKeyLength },
    {(const sbyte*)"tag",       3, kAeadTag },
    {(const sbyte*)"sa",        2, kSaAttr },

    {(const sbyte*)"lifetime_secs",  13, kExpSecs },
    {(const sbyte*)"lifetime_bytes", 14, kExpBytes },

    {(const sbyte*)"traddr",    6, kTunnelRAddr },
    {(const sbyte*)"tladdr",    6, kTunnelLAddr }
};

/* possible authentication names */
static Token gAuthenticationTokens[] =
{
    {(const sbyte*)"any",       3, IPSEC_AUTHALG_ANY },
    {(const sbyte*)"md5",       3, IPSEC_AUTHALG_MD5 },
    {(const sbyte*)"sha1",      4, IPSEC_AUTHALG_SHA1 },
    {(const sbyte*)"aes",       3, IPSEC_AUTHALG_AES },
    {(const sbyte*)"sha256",    6, IPSEC_AUTHALG_SHA256 },
    {(const sbyte*)"sha384",    6, IPSEC_AUTHALG_SHA384 },
    {(const sbyte*)"sha512",    6, IPSEC_AUTHALG_SHA512 },
    {(const sbyte*)"blake2b",   7, IPSEC_AUTHALG_BLAKE2_2B },
    {(const sbyte*)"blake2s",   7, IPSEC_AUTHALG_BLAKE2_2S }
};

/* possible encryption names */
static Token gEncryptionTokens[] =
{
    {(const sbyte*)"any",       3, IPSEC_ENCALG_ANY },
    {(const sbyte*)"aes",       3, IPSEC_ENCALG_AES },
    {(const sbyte*)"des",       3, IPSEC_ENCALG_DES },
    {(const sbyte*)"3des",      4, IPSEC_ENCALG_3DES},
    {(const sbyte*)"blowfish",  8, IPSEC_ENCALG_BLOWFISH},
    {(const sbyte*)"gcm",       3, IPSEC_ENCALG_AES_GCM},
    {(const sbyte*)"gmac",      4, IPSEC_ENCALG_AES_GMAC},
    {(const sbyte*)"ccm",       3, IPSEC_ENCALG_AES_CCM},
    {(const sbyte*)"ctr",       3, IPSEC_ENCALG_AES_CTR},
    {(const sbyte*)"chacha20-poly1305",  17, IPSEC_ENCALG_CHACHA20_POLY1305},
};

/* possible sa attributes */
static Token gSaAttrTokens[] =
{
    {(const sbyte*)"shared",    6, 0},
    {(const sbyte*)"init",      4, IPSEC_SP_FLAG_INIT}
};

/* possible commands */
static Token gCommandTokens[] =
{
    {(const sbyte*)"add",       3, kAdd},
    {(const sbyte*)"flush",     5, kFlush},
    {(const sbyte*)"spdflush",  8, kSpdFlush}
};

/* possible modes */
static Token gModeTokens[] =
{
    {(const sbyte*)"transport", 9, IPSEC_MODE_TRANSPORT},
    {(const sbyte*)"tunnel",    6, IPSEC_MODE_TUNNEL},
    {(const sbyte*)"any",       3, 0}
};

/* possible authentication algorithm names */
static Token gAuthAlgoTokens[] =
{
    {(const sbyte*)"hmac-md5",      8,  IPSEC_AUTHALG_MD5 },
    {(const sbyte*)"hmac-sha1",     9,  IPSEC_AUTHALG_SHA1 },
    {(const sbyte*)"aes-xcbc-mac",  12, IPSEC_AUTHALG_AES },
    {(const sbyte*)"hmac-sha256",   11, IPSEC_AUTHALG_SHA256 },
    {(const sbyte*)"hmac-sha384",   11, IPSEC_AUTHALG_SHA384 },
    {(const sbyte*)"hmac-sha512",   11, IPSEC_AUTHALG_SHA512 },
    {(const sbyte*)"blake2b",       7,  IPSEC_AUTHALG_BLAKE2_2B },
    {(const sbyte*)"blake2s",       7,  IPSEC_AUTHALG_BLAKE2_2S }
};

/* possible encryption algorithm names */
static Token gEncrAlgoTokens[] =
{
    {(const sbyte*)"aes-cbc",       7,  IPSEC_ENCALG_AES},
    {(const sbyte*)"des-cbc",       7,  IPSEC_ENCALG_DES },
    {(const sbyte*)"3des-cbc",      8,  IPSEC_ENCALG_3DES},
    {(const sbyte*)"blowfish-cbc",  12, IPSEC_ENCALG_BLOWFISH},
    {(const sbyte*)"aes-ctr",       7,  IPSEC_ENCALG_AES_CTR}
};

#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
static struct ipsecConf m_activeGroupAddress[MAX_GROUP_NEGOTIATION] = {0};
static ubyte4 activeGroupAddressIndex = 0;
static struct sainfo pSAInfo[MAX_GROUP_NEGOTIATION] = {{0}};
#endif


#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
sbyte m_configured_fqdnList[MAX_UNICAST_GROUP][MOC_MAX_FQDN_LEN];
ubyte4 m_groupListCount ;
fqdnUnicastGroupConfig m_fqdnGroupList[MAX_UNICAST_GROUP] = {0}; /* FQDN unicast group list */
ubyte m_rangeCount = 0;
MOC_IP_ADDRESS_S m_startRangeIP[MAX_UNICAST_RANGE];
MOC_IP_ADDRESS_S m_endRangeIP[MAX_UNICAST_RANGE];

ubyte4 m_hostIpAddr[MAX_HOST_IP] = {0};
#endif

sbyte **hostAddr = NULL;    /* maintain multiple host adddresses*/

/* temporary flags for 2 differnt scripting styles (used in this file only) */
#define IPSEC_DIR_SOLARIS_8 0x40
#define IPSEC_DIR_SOLARIS_9 0x80

#ifdef __ENABLE_DIGICERT_IPV6__
/* temporary flags for IPv4 addresses (used in this file only)
   warning: make sure to check against "spd.h"
 */
#define IPSEC_SP_FLAG_IP4        0x01
#define IPSEC_SP_FLAG_IP4_TUNNEL 0x02
static sbyte4
CheckIpRange6(const ubyte *poAddr, const ubyte *poIP, const ubyte* poIPEnd);

#endif


/*-----------------------------------------------------------------------*/

extern void
RemoveDotIP4Addr(const sbyte* pNextToken, ubyte4* ipAddress)
{
    ubyte4 i=0;
    ubyte4 num=0;
    for(i = 0; i < 4; i++)
    {
            num = (ubyte4)DIGI_ATOL(pNextToken, NULL);
            *ipAddress <<= 8;
            *ipAddress += num;
            while((*pNextToken != '.') && (i != 3))
            {
                    pNextToken++;
                    continue;
            }
            pNextToken++;
    }
}


/*-----------------------------------------------------------------------*/

extern sbyte4
CheckIpInUnicastRange(MOC_IP_ADDRESS snAddr, MOC_IP_ADDRESS snAddrEnd,
             MOC_IP_ADDRESS ipAddr, MOC_IP_ADDRESS ipAddrEnd)
{
    sbyte4 status = 0;

#ifdef __ENABLE_DIGICERT_IPV6__
    if (AF_INET6 == ipAddr->family)
    {
        if (AF_INET6 == snAddr->family)
        {
            if (0 == (status = CheckIpRange6(GET_MOC_IPADDR6(ipAddr),
                                             GET_MOC_IPADDR6(snAddr),
                                             GET_MOC_IPADDR6(snAddrEnd))))
            {
                if (ipAddrEnd)
                {
                    status = CheckIpRange6(GET_MOC_IPADDR6(ipAddrEnd),
                                           GET_MOC_IPADDR6(snAddr),
                                           GET_MOC_IPADDR6(snAddrEnd));
                }
            }
        }
        else status = 1;
    }
    else if (AF_INET6 == snAddr->family) status = -1;
    else
#endif
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte4 dwIP = GET_MOC_IPADDR4(snAddr);
        ubyte4 dwIPEnd = GET_MOC_IPADDR4(snAddrEnd);
        ubyte4 dwAddr = GET_MOC_IPADDR4(ipAddr);
        ubyte4 dwAddrEnd = (ipAddrEnd ? GET_MOC_IPADDR4(ipAddrEnd) : 0);
#else
        #define dwIP        snAddr
        #define dwIPEnd     snAddrEnd
        #define dwAddr      ipAddr
        #define dwAddrEnd   ipAddrEnd
#endif
        if (!dwIPEnd) /* just in case */
            dwIPEnd = (dwIP ? dwIP : ~((ubyte4)0));

        if (dwAddr < dwIP) status = -1;
        else if (dwAddr > dwIPEnd) status = 1;

        if (!status)
        {
            if (!dwAddrEnd && !dwAddr) /* just in case */
                dwAddrEnd = ~((ubyte4)0);

            if (dwAddrEnd)
            {
                if (dwAddrEnd < dwIP) status = -1;
                else if (dwAddrEnd > dwIPEnd) status = 1;
            }
        }
#ifndef __ENABLE_DIGICERT_IPV6__
        #undef dwIP
        #undef dwIPEnd
        #undef dwAddr
        #undef dwAddrEnd
#endif
    }

    return status;
} /* CheckIpInUnicastRange */


/*-----------------------------------------------------------------------*/

static intBoolean
IsWhiteSpace( sbyte c)
{
    return ' ' == c || '\t' == c || '\n' == c || '\r' == c;
}


/*-----------------------------------------------------------------------*/

static intBoolean
IsTokenDelimiter( sbyte c)
{
    return 0 == c || IsWhiteSpace(c) ||
        '{' == c || '}' == c ||
        '[' == c || ']' == c ||
        '.' == c || '/' == c;
}

/*-----------------------------------------------------------------------*/

static const sbyte*
SkipComment( const sbyte* s)
{
    /* advance until the next end of line */
    while (*s && '\n' != *s)
    {
        ++s;
    }
    return s;
}


/*------------------------------------------------------------------------*/

static const sbyte*
GetNextToken( const sbyte* s)
{
    while (*s)
    {
        sbyte c = *s;
        if (IsWhiteSpace(c))
        {
            ++s;
        }
        else if ( '#' == c)
        {
            s = SkipComment( ++s);
        }
        else
        {
            break;
        }
    }
    return s;
}


/*------------------------------------------------------------------------*/

static intBoolean
IsToken( const sbyte* s, Token* pToken)
{
    sbyte4 cmpRes;

    DIGI_MEMCMP( (const ubyte*) pToken->m_str,
                (const ubyte*) s,
                pToken->m_len,
                &cmpRes);
    return ( 0 == cmpRes && IsTokenDelimiter( s[pToken->m_len]));
}


/*------------------------------------------------------------------------*/

static MSTATUS
ReadNumber( const sbyte** pNextToken, sbyte4* number)
{
    int numDigitsRead = 0;
    const sbyte* s = *pNextToken;

    *number = 0;

    /* check hexadecimal number, e.g. 0x... */
    if ( 0 == DIGI_STRNICMP(s, (sbyte *)"0x", 2))
    {
        s += 2;
        for (;; s++)
        {
            sbyte c = *s;
            if ( c >= '0' && c <= '9') c -= '0';
            else if ( c >= 'a' && c <= 'f') c -= 'a' - 10;
            else if ( c >= 'A' && c <= 'F') c -= 'A' - 10;
            else break;

            ++numDigitsRead;
            *number *= 16;
            *number += c;
        }

        if ( 8 < numDigitsRead) return ERR_FALSE;
    }
    else

    while ( *s >= '0' && *s <= '9')
    {
        ++numDigitsRead;
        *number *= 10;
        *number += (*s++) - '0';
    }

    *pNextToken = s;
    return ( numDigitsRead) ? OK : ERR_FALSE;
}


/*------------------------------------------------------------------------*/

static sbyte4
GetNameLength( const sbyte* token)
{
    sbyte4 retVal = 0;
    /* return the number of chars that are chars, digits or .
     (use this to read port, DNS names, etc...*/
    while ( (*token >= '0' && *token <= '9') ||
            ('.' == *token) ||
#ifdef __ENABLE_DIGICERT_IPV6__
            (':' == *token) ||
            ('%' == *token) ||
#endif
            ('_' == *token) ||
            ('-' == *token) ||
            (*token >= 'A' && *token <= 'Z') ||
            (*token >= 'a' && *token <= 'z') )
    {
        ++retVal;
        ++token;
    }
    return retVal;
}

/*------------------------------------------------------------------------*/

static MSTATUS
ParseIP4Address(const sbyte** pNextToken, ubyte4* ipAddress)
{
    const sbyte* s = *pNextToken;
    sbyte4 i;
    sbyte4 readNumber;

    *ipAddress = 0;
    for (i = 0; i < 4; ++i)
    {
        MSTATUS status = ReadNumber( &s, &readNumber);
        if (OK == status && ('.' == *s || 3 == i))
        {
            if ( '.' == *s)
            {
                ++s;
            }
            *ipAddress <<= 8;
            *ipAddress += (ubyte4) readNumber;
        }
        else
        {
            return ERR_IPSEC_SCRIPT_BAD_IPADDRESS;
        }
    }
    *pNextToken = s;
    return OK;
}


/*------------------------------------------------------------------------*/

#define IS_HEX(a) \
    ( ((a) >= '0' && (a) <= '9') || \
      ((a) >= 'A' && (a) <= 'F') || \
      ((a) >= 'a' && (a) <= 'f') )

sbyte char2nibble(sbyte c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 0xA;
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 0xa;
    else
        return -1;
}

#ifdef __ENABLE_DIGICERT_IPV6__


/*------------------------------------------------------------------*/

extern sbyte4
CmpIpAddr6(const ubyte *poIP1, const ubyte *poIP2)
{
    sbyte4 status = 0;
    sbyte4 i;

    if (poIP1 != poIP2)
    {
        if (!poIP1) status = -1;
        else if (!poIP2) status = 1;
        else
        for (i=0; i < 4; i++)
        {
            ubyte4 x = DIGI_NTOHL(poIP1 + (i * 4));
            ubyte4 y = DIGI_NTOHL(poIP2 + (i * 4));
            if (x < y) { status = -1; break; }
            if (x > y) { status = 1; break; }
        }
    }

    return status;
} /* CmpIpAddr6 */


/*------------------------------------------------------------------*/

static sbyte4
CheckIpRange6(const ubyte *poAddr, const ubyte *poIP, const ubyte* poIPEnd)
{
    sbyte4 status;

    if ((0 <= (status = CmpIpAddr6(poAddr, poIP))) &&
        (0 >= (status = CmpIpAddr6(poAddr, poIPEnd))))
    {
        status = 0;
    }
    return status;
} /* CheckIpRange6 */




static MSTATUS
ParseIP6Address(const sbyte** pNextToken, ubyte** ip6Addr)
{
    const sbyte* s = *pNextToken;
    ubyte2 values[8];
    ubyte *output = *ip6Addr;
    int i, zerosAfter, zeros, j, num;

    /* find out how many zeros '::' represents */
    i = 0;
    zerosAfter = -1;
    while (!(IsWhiteSpace(*s) || *s == 0 || *s == '/'))
    {
        if (*s == ':')
        {
            s++;
            if (*s == ':')
            {
                /* Remember to insert zeros before digit i */
                zerosAfter = i;
                s++;
            }
        }
        else if (IS_HEX(*s))
        {
            /* this is a 16-bit hex digit.  Convert it accordingly */
            ubyte2 value = 0;
            while (IS_HEX(*s))
            {
                value <<= 4;
                value |= char2nibble(*s);
                s++;
            }
            values[i] = value;
            i++;
        }
        else
        {
            return ERR_IPSEC_SCRIPT_BAD_IPADDRESS;
        }
    }
    *pNextToken = s;

    /* now populate the ip address array in network order from the array of
     * values
     */
    zeros =  8 - i;
    num = i - 1;
    i = 0;
    while (i <= num)
    {

        if (zerosAfter != -1 && i == zerosAfter)
        {
            /* insert zeros before this address */
            for (j = 0; j < zeros; j++)
            {
                *output++ = 0;
                *output++ = 0;
            }
        }
        *output++ = (ubyte)((values[i] >> 8) & 0xff);
        *output++ = (ubyte)(values[i] & 0xff);
        i++;
    }

    /* All values are in.  Now add any trailing zeros */
    if (zerosAfter == i)
    {
        for (j = 0; j < zeros; j++)
        {
            *output++ = 0;
            *output++ = 0;
        }
    }

    return OK;
}
#endif /* __ENABLE_DIGICERT_IPV6__ */

/*------------------------------------------------------------------------*/

static MSTATUS
MatchVariable( const sbyte** pNextToken, const DynArray* pVars,
              sbyte4 *extra)
{
    MSTATUS status = ERR_NOT_FOUND;
    const sbyte* s = *pNextToken;
    sbyte4 i;
    sbyte4 numElems;
    Token token;

    DYNARR_GetElementCount( pVars, &numElems);

    /* try to match one of the token */
    for ( i = 0; i < numElems; ++i)
    {
        DYNARR_Get( pVars, i, &token);

        if (IsToken( s, &token))
        {
            *extra = token.m_extra;
            s += token.m_len;
            status = OK;
            break;
        }
    }

    *pNextToken = s;
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
MatchToken( const sbyte** pNextToken, Token* tokenTable,
           sbyte4 tokenTableLen, sbyte4 *extra)
{
    MSTATUS status = ERR_NOT_FOUND;
    const sbyte* s = *pNextToken;
    sbyte4 i;

    /* try to match one of the token */
    for ( i = 0; i < tokenTableLen; ++i)
    {
        if (IsToken( s, tokenTable + i))
        {
            *extra = tokenTable[i].m_extra;
            s += tokenTable[i].m_len;
            status = OK;
            break;
        }
    }

    *pNextToken = s;
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseDir( const sbyte** pNextToken, ubyte4 *dir)
{
    MSTATUS status = MatchToken( pNextToken,
                            gDirectionTokens,
                            COUNTOF(gDirectionTokens),
                            (sbyte4*) dir);
    if ( OK > status)
    {
        status = ERR_IPSEC_SCRIPT_UNKNOWN_DIRECTION;
    }
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseAuthAlg( const sbyte** pNextToken, ubyte4 *auth)
{
    MSTATUS status = MatchToken( pNextToken,
                            gAuthenticationTokens,
                            COUNTOF(gAuthenticationTokens),
                            (sbyte4*) auth);
    if ( OK > status)
    {
        status = ERR_IPSEC_SCRIPT_UNKNOWN_AUTH_ALG;
    }
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseEncrAlg( const sbyte** pNextToken, ubyte4 *encr)
{
    MSTATUS status = MatchToken( pNextToken,
                            gEncryptionTokens,
                            COUNTOF(gEncryptionTokens),
                            (sbyte4*) encr);
    if ( OK > status)
    {
        status = ERR_IPSEC_SCRIPT_UNKNOWN_ENCR_ALG;
    }
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseSaAttr( const sbyte** pNextToken, ubyte4 *attr)
{
    MSTATUS status = MatchToken( pNextToken,
                            gSaAttrTokens,
                            COUNTOF(gSaAttrTokens),
                            (sbyte4*) attr);
    if ( OK > status)
    {
        status = ERR_IPSEC_SCRIPT_UNKNOWN_PROPERTY;
    }
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseNumber( const sbyte** pNextToken, const DynArray* pVars, sbyte4 *number)
{
    MSTATUS status = ReadNumber( pNextToken, number);

    if (OK > status)
    {
        status = MatchVariable( pNextToken, pVars, number);
    }
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseUlp( const sbyte** pNextToken, const DynArray* pVars, ubyte4 *ulp)
{
    MSTATUS status = ParseNumber( pNextToken, pVars, (sbyte4*) ulp);

    if ( OK > status )
    {
        status = MatchToken( pNextToken,
                            gProtocolTokens,
                            COUNTOF(gProtocolTokens),
                            (sbyte4*) ulp);
    }

    if ( OK > status)
    {
        status = ERR_IPSEC_SCRIPT_UNKNOWN_PROTOCOL;
    }
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParsePort( const sbyte** pNextToken, const DynArray* pVars, ubyte4 *port)
{
    MSTATUS status = ParseNumber( pNextToken, pVars, (sbyte4*) port);

    if ( OK > status )
    {
        status = MatchToken( pNextToken, gPortTokens, COUNTOF( gPortTokens), (sbyte4*) port);
    }
    if ( OK > status)
    {
        status = ERR_IPSEC_SCRIPT_UNKNOWN_PORT;
    }

    return status;
}

/*------------------------------------------------------------------------*/

static MSTATUS
ParsePortList(const sbyte** pNextToken, ubyte4 *id)
{
    MSTATUS status = OK;
    ubyte pPortListKey[20] = {0};
    sbyte c;

    ubyte port_list_len = GetNameLength(*pNextToken);
    DIGI_MEMCPY(pPortListKey, *pNextToken, port_list_len);

    if (0 == m_ipsec_portlist[0].key[0])
    {
        DEBUG_PRINT(DEBUG_CUSTOM, (sbyte *)"\nPort list mapping file not configured in mcp.conf/agent.ini\n");
        status = ERR_IPSEC_SCRIPT_UNKNOWN_PORT_LIST;
        return status;
    }
    int i = 0;
    for (i = 0; i < MAX_NUM_ADDRESS_TRANSLATION; i++)
    {
        /* skip individual port address mappings */
        if (0 != m_ipsec_portlist[i].key[0])
        {
            /* found */
            if (0 == DIGI_STRCMP((sbyte *) m_ipsec_portlist[i].key, (sbyte *)pPortListKey))
            {
                *id = i;
                break;
            }
        }
    }

    while (**pNextToken)
    {
        c = **pNextToken;
        if (!(IsWhiteSpace(c) || ('}' == c)))
        {
            ++(*pNextToken);
        }
        else
        {
            break;
        }
    }

    /* invalid agent.policy lport_list entry */
    if ( i == MAX_NUM_ADDRESS_TRANSLATION )
    {
        DEBUG_PRINT(DEBUG_CUSTOM, (sbyte *)"\nUnknown port list configured in policy file\n");
        status = ERR_IPSEC_SCRIPT_UNKNOWN_PORT_LIST;
    }

    return status;
}

/*------------------------------------------------------------------------*/

static MSTATUS
ParseHostName( const sbyte** pNextToken, const DynArray* pVars,
               CAST_MOC_IPADDR *ipAddress
#ifdef __ENABLE_DIGICERT_IPV6__
             , ubyte** ip6Addr
#endif
              )
{
    MSTATUS status;

    sbyte4 var;
    status = MatchVariable( pNextToken, pVars, &var);

    if  (OK > status)
    {
        /* search our lookup table second */
        status = MatchToken( pNextToken, gHostTokens,
                            COUNTOF(gHostTokens), &var);
    }
    if ( OK > status ) /* DNS Look up */
    {
        sbyte* name = 0;
        sbyte4 lenName = GetNameLength( *pNextToken);

        name = (sbyte*) MALLOC( lenName+1);
        if( name)
        {
            if ( OK == DIGI_MEMCPY( (ubyte*) name, (ubyte*) *pNextToken, lenName))
            {
#if (defined(__LINUX_RTOS__) && defined(__KERNEL__)) || \
    (defined(__QNX_RTOS__) && defined(_KERNEL)) || \
    (defined(__OSE_RTOS__) && defined(IPCOM_KERNEL))

                status = ERR_UDP_HOSTNAME_NOT_FOUND; /* for now */
#else
                MOC_IP_ADDRESS_S addr;
                name[lenName] = 0;
                status = UDP_getAddrOfHost( name, &addr);
                if (OK == status)
                {
#ifdef __ENABLE_DIGICERT_IPV6__
                    if (AF_INET6 == addr.family)
                    {
                        /* pointer to IPv6 addr buffer!!! */
                        *ipAddress = (CAST_MOC_IPADDR)(uintptr_t)(*ip6Addr);
                        DIGI_MEMCPY(*ip6Addr, RET_MOC_IPADDR6(addr), 16);
                    }
                    else
                    {
                        *ip6Addr = 0;
                        *ipAddress = RET_MOC_IPADDR4(addr);
                    }
#else
                    *ipAddress = addr;
#endif
                }
#endif
            }
            FREE( name);
        }
        else
        {
            status = ERR_MEM_ALLOC_FAIL;
        }

        *pNextToken += lenName;
    }
    else
    {
        *ipAddress = var;
#ifdef __ENABLE_DIGICERT_IPV6__
        *ip6Addr = 0;
#endif
    }

    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseAddress( const sbyte** pNextToken, const DynArray* pVars,
              CAST_MOC_IPADDR *ipAddress
#ifdef __ENABLE_DIGICERT_IPV6__
            , ubyte** ip6Addr
#endif
             )
{
    MSTATUS status;

    /* is the address in IPv4 dot notation? */
    ubyte4 ip4Addr;
    status = ParseIP4Address( pNextToken, &ip4Addr);
    if ( OK == status)
    {
        *ipAddress = ip4Addr;
#ifdef __ENABLE_DIGICERT_IPV6__
        *ip6Addr = 0;
#endif
        return status;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    /* is the address in IPv6 notation? */
    status = ParseIP6Address( pNextToken, ip6Addr);
    if ( OK == status)
    {
        *ipAddress = (CAST_MOC_IPADDR)(uintptr_t)(*ip6Addr);
        return status;
    }
#endif

    /* if all else fails, try a host name */
    status = ParseHostName( pNextToken, pVars, ipAddress
#ifdef __ENABLE_DIGICERT_IPV6__
                            , ip6Addr
#endif
                           );
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseAddresses( const sbyte** pNextToken, const DynArray* pVars,
                CAST_MOC_IPADDR *ipAddress1, CAST_MOC_IPADDR *ipAddress2
#ifdef __ENABLE_DIGICERT_IPV6__
              , ubyte** ip6Addr
#endif
                )
{
    MSTATUS status;
    ubyte4 prefix = 32; /* default */

    *ipAddress1 = *ipAddress2 = 0;

    status = ParseAddress( pNextToken, pVars, ipAddress1
#ifdef __ENABLE_DIGICERT_IPV6__
                         , ip6Addr
#endif
                           );
    if ( OK > status)
    {
        return status;
    }

#ifdef __ENABLE_DIGICERT_IPV6__
    if (*ip6Addr)
    {
        *ipAddress1 = (CAST_MOC_IPADDR)(uintptr_t)(*ip6Addr);
    }
#endif

    if('-' == **pNextToken) /* range prefix*/
    {
        ++(*pNextToken);
        status = ParseAddress( pNextToken, pVars, ipAddress2
#ifdef __ENABLE_DIGICERT_IPV6__
                     , ip6Addr
#endif
                       );
        if ( OK > status)
        {
            return status;
        }

#ifdef __ENABLE_DIGICERT_IPV6__
        if (*ip6Addr)
        {
            *ipAddress2 = (CAST_MOC_IPADDR)(uintptr_t)(*ip6Addr);
        }
#endif

    }
    if ('/' == **pNextToken) /* prefix */
    {
        ++(*pNextToken);
        status = ParseNumber(pNextToken, pVars, (sbyte4*) &prefix);
        if ( OK == status)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (*ip6Addr)
            {
                if (prefix < 128)
                {
                    ubyte *addr_start = *ip6Addr;
                    ubyte *addr_end = addr_start + 16;

                    sbyte4 i;
                    for (i=0; i < 16; i++)
                    {
                        if (8 <= prefix)
                        {
                            addr_end[i] = addr_start[i];
                            prefix -= 8;
                        }
                        else if (prefix)
                        {
                            ubyte m = (ubyte)(0xFF << (8 - prefix));
                            addr_end[i] = (ubyte)(addr_start[i] | (ubyte)(~m));
                            addr_start[i] = (ubyte)(addr_start[i] & m);
                            prefix = 0;
                        }
                        else
                        {
                            addr_start[i] = (ubyte)0x00;
                            addr_end[i] = (ubyte)0xFF;
                        }
                    }

                    *ipAddress2 = (*ipAddress1) + 16;
                }
            }
            else
#endif
            if (prefix < 32)
            {
                /* apply the mask */
                unsigned m = 0xFFFFFFFFU;
                m <<= (32 - prefix);
                *ipAddress1 &= m;
                *ipAddress2 = (*ipAddress1) | (~m);
            }
        }
    }
    return OK;
}


/*------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
static MSTATUS
validateFqdnHostAddresses(ubyte* pToken, ubyte4 fqdnGroupIndex)
{
     MSTATUS status = OK;
     ubyte4 hostIpIndex = 0;
     /*ubyte4 fqdnGroupIndex = 0;*/
     byteBoolean is_host_found = FALSE;
     CAST_MOC_IPADDR ipAddress;
     status = ParseAddress((const sbyte**) &pToken, NULL, &ipAddress);
     is_host_found = FALSE;

     /*MOC_GROUP_FIND_FQDN(pIPSecConf->fqdn, fqdnGroupIndex, isFqdnFound);*/

    while (hostIpIndex < m_fqdnGroupList[fqdnGroupIndex].hostIPCount)
    {
        if(m_fqdnGroupList[fqdnGroupIndex].hostIp[hostIpIndex] == ipAddress)
        {
            is_host_found = TRUE;
        }
        hostIpIndex++;
    }

     if (!is_host_found)
     {
         status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
         goto exit;
     }

exit:
    return status;
}
#endif

/*------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
extern MSTATUS MCP_getGroupType(const sbyte *pGroupName, ubyte4 *pGroupType, sbyte **ppGroupValue);
#endif

static MSTATUS
ParsePatternNameValuePair( const sbyte** pNextToken, const DynArray* pVars,
                          IPSECCONF pIPSecConf)
{
    MSTATUS status = OK;
    CAST_MOC_IPADDR data1, data2;
    ubyte4 data;
    sbyte4 token;
    ubyte4 id = 0;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    ubyte4 copyLen;
#endif

    status = MatchToken( pNextToken, gPatternTokens,
                            COUNTOF( gPatternTokens), &token);

    if ( OK > status)
    {
        return ERR_IPSEC_SCRIPT_UNKNOWN_PATTERN;
    }

    *pNextToken = GetNextToken(*pNextToken);
    switch (token)
    {
    case kRAddr:
    case kRPort:
    case kLAddr:
    case kLPort:
    case kPortList:
    case kLPortList:
    case kRAddrList:
    case kLAddrList:
    case kLAddrEx:
        if (IPSEC_DIR_SOLARIS_8 & pIPSecConf->oDir)
        {
            status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
            goto exit;
        }
        pIPSecConf->oDir |= IPSEC_DIR_SOLARIS_9;
        break;

    case kSAddr:
    case kSPort:
    case kDAddr:
    case kDPort:
        if (IPSEC_DIR_SOLARIS_9 & pIPSecConf->oDir)
        {
            status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
            goto exit;
        }
        pIPSecConf->oDir |= IPSEC_DIR_SOLARIS_8;
        break;
    }

    switch (token)
    {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    case kRAddrList:
    case kLAddrList:
    {
        /* Get the length of unicast list group entry here*/
        ubyte group_len = GetNameLength(*pNextToken);
#ifdef __ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__
        ubyte4 groupType = 0;
        sbyte *pGroupValue = NULL;
        sbyte *pTmp = NULL;
        sbyte pCurToken[32] = {0};

        DIGI_MEMCPY(pCurToken, *pNextToken, (group_len > sizeof(pCurToken))? sizeof(pCurToken):group_len);
        status = MCP_getGroupType((const sbyte *)pCurToken, &groupType, &pGroupValue);
        if (OK != status)
        {
            DIGI_FREE((void **) &pGroupValue);
            goto exit;
        }
        if (MOC_MCP_UNICAST_LIST == groupType) {
#endif
            copyLen = (group_len < (sizeof(pIPSecConf->fqdn) - 1)) ?
                                group_len : (sizeof(pIPSecConf->fqdn) - 1);
            DIGI_MEMCPY(pIPSecConf->fqdn, *pNextToken, copyLen);
            pIPSecConf->fqdn[copyLen] = '\0';
            pIPSecConf->isUnicastGDOI = 1;
#ifdef __ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__
            DIGI_FREE((void **) &pGroupValue);
        } else if ((MOC_MCP_UNICAST_RANGE == groupType) || (MOC_MCP_UNICAST_SUBNET == groupType)) {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (kLAddrList == token) {
                ubyte* ip6Addr = (ubyte*)(pIPSecConf + 1) + (16 * 2);
            } else {
                ubyte* ip6Addr = (ubyte*)(pIPSecConf + 1);
            }
#endif
            pTmp = pGroupValue; /* original pointer is modified, pass copy of pointer */
            status = ParseAddresses((const sbyte **) &pTmp, pVars, &data1, &data2
#ifdef __ENABLE_DIGICERT_IPV6__
                                , &ip6Addr
#endif
                                    );
            DIGI_FREE((void **) &pGroupValue);
            if ( OK == status)
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                if (ip6Addr)
                {
                    if (IPSEC_SP_FLAG_IP4 & pIPSecConf->flags)
                    {
                        status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                        break;
                    }
                    pIPSecConf->flags |= IPSEC_SP_FLAG_IP6;
                }
                else
                {
                    if (IPSEC_SP_FLAG_IP6 & pIPSecConf->flags)
                    {
                        status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                        break;
                    }
                    pIPSecConf->flags |= IPSEC_SP_FLAG_IP4;
                }
#endif

                if (kLAddrList == token) {
                    pIPSecConf->dwDestIP = data1;
                    pIPSecConf->dwDestIPEnd = data2;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                    if(pIPSecConf->dwDestIPEnd != 0) /* For unicast IP range */
                    {
                        pIPSecConf->isGdoi = 1;
                    }
#endif
                } else {
                    pIPSecConf->dwSrcIP = data1;
                    pIPSecConf->dwSrcIPEnd = data2;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
                    if(pIPSecConf->dwSrcIPEnd != 0) /* For unicast IP range */
                    {
                        pIPSecConf->isGdoi = 1;
                    }
#endif
                }
            }
        }
#endif /* __ENABLE_DIGICERT_MCP_TRUSTEDGE_MODE__ */
        *pNextToken += group_len;
        break;
    }
     case kLAddrEx:
     {
         ubyte4 fqdnGroupIndex = 0;
         sbyte isFqdnFound = FALSE;
         MOC_GROUP_FIND_FQDN(pIPSecConf->fqdn, fqdnGroupIndex, isFqdnFound);
         if (!isFqdnFound)
         {
             while (' ' != **pNextToken)
                 (*pNextToken)++;
         }
         else
         {
             ubyte4 ipListIndex = 0;
             ubyte4 ipCount = 0;
             ubyte4 strCount = 0;
             byteBoolean is_host = FALSE;

             ubyte pToken[32];
             ubyte* tmpStr = (ubyte *)*pNextToken;
             ubyte* IPListPerGroup[MAX_HOST_IP];

             while (' ' != tmpStr[strCount])
             {
                 if (',' != tmpStr[strCount])
                 {
                     pToken[ipCount] = tmpStr[strCount];
                     ipCount++;
                 }
                 else
                 {
                     pToken[ipCount] = '\0';
                     if (OK > (status = validateFqdnHostAddresses(pToken, fqdnGroupIndex)))
                     {
                         goto exit;
                     }
                     ipListIndex++;
                     ipCount = 0;
                 }
                 strCount++;
             }
             (*pNextToken) += strCount;
             if (0 < ipListIndex)
                 pToken[ipCount] = '\0';
             if (OK > (status = validateFqdnHostAddresses(pToken, fqdnGroupIndex)))
             {
                 goto exit;
             }
             ipListIndex++;

             if(ipListIndex != m_fqdnGroupList[fqdnGroupIndex].hostIPCount)
             {
                 status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
                 goto exit;
             }
         }
         break;
     }
#endif
    case kRAddr:
    case kSAddr:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte* ip6Addr = (ubyte*)(pIPSecConf + 1);
#endif
        status = ParseAddresses( pNextToken, pVars, &data1, &data2
#ifdef __ENABLE_DIGICERT_IPV6__
                               , &ip6Addr
#endif
                                );
        if ( OK == status)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (ip6Addr)
            {
                if (IPSEC_SP_FLAG_IP4 & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP6;
            }
            else
            {
                if (IPSEC_SP_FLAG_IP6 & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP4;
            }
#endif
            pIPSecConf->dwSrcIP = data1;
            pIPSecConf->dwSrcIPEnd = data2;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
            if(pIPSecConf->dwSrcIPEnd != 0) /* For unicast IP range */
            {
                pIPSecConf->isGdoi = 1;
            }
#endif
        }
        break;
    }
    case kRPort:
    case kSPort:
        status = ParsePort(pNextToken, pVars, &data);
        if (OK == status)
        {
            pIPSecConf->wSrcPort = (ubyte2)data;
            pIPSecConf->srcPortType = MCP_SINGLE_PORT;
        }
        break;
    case kPortList:
        status = ParsePortList(pNextToken, &id);
        if (OK == status)
        {
            ubyte4 i = 0;
            for (i = 0; i < m_ipsec_portlist[id].port_mapping_count; i++)
            {
                pIPSecConf->wPortList[i] = m_ipsec_portlist[id].port_mapping_list[i];
            }
            pIPSecConf->wPortCount = m_ipsec_portlist[id].port_mapping_count;
        }
        break;
    case kLAddr:
    case kDAddr:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte* ip6Addr = (ubyte*)(pIPSecConf + 1) + (16 * 2);
#endif
        status = ParseAddresses( pNextToken, pVars, &data1, &data2
#ifdef __ENABLE_DIGICERT_IPV6__
                               , &ip6Addr
#endif
                                );
        if ( OK == status)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (ip6Addr)
            {
                if (IPSEC_SP_FLAG_IP4 & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP6;
            }
            else
            {
                if (IPSEC_SP_FLAG_IP6 & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP4;
            }
#endif
            pIPSecConf->dwDestIP = data1;
            pIPSecConf->dwDestIPEnd = data2;
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
            if(pIPSecConf->dwDestIPEnd != 0) /* For unicast IP range */
            {
                pIPSecConf->isGdoi = 1;
            }
#endif
        }
        break;
    }
    case kLPort:
    case kDPort:
        status = ParsePort(pNextToken, pVars, &data);
        if (OK == status)
        {
            pIPSecConf->wDestPort = (ubyte2)data;
            pIPSecConf->destPortType = MCP_SINGLE_PORT;
        }
        break;

    case kLPortList:
        status = ParsePortList(pNextToken, &id);
        if (OK == status)
        {
            ubyte4 i = 0;
            for (i = 0; i < m_ipsec_portlist[id].port_mapping_count; i++)
            {
                pIPSecConf->wDestPortList[i] = m_ipsec_portlist[id].port_mapping_list[i];
            }
            pIPSecConf->destPortType = MCP_PORT_LIST;
            pIPSecConf->wDestPortCount = m_ipsec_portlist[id].port_mapping_count;
        }
        break;

    case kUlp:
        status = ParseUlp(pNextToken, pVars, &data);
        if (OK == status)
        {
            pIPSecConf->oProto = (ubyte)data;
        }
        break;

    case kDir:
        status = ParseDir(pNextToken, &data);
        if (OK == status)
        {
            if (((IPSEC_DIR_OUTBOUND & data) &&
                 (IPSEC_DIR_INBOUND & pIPSecConf->oDir)) ||
                ((IPSEC_DIR_INBOUND & data) &&
                 (IPSEC_DIR_OUTBOUND & pIPSecConf->oDir)))
            {
                status = ERR_IPSEC_SCRIPT_BAD_DIRECTION;
                break;
            }
            pIPSecConf->oDir |= (ubyte)data;
        }
        break;
#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    case kIfId:
        status = ParseNumber(pNextToken, pVars, (sbyte4 *)&data);
        if (OK == status)
        {
            pIPSecConf->ifid = (sbyte4)data;
        }
        else
        {
            status = ERR_IPSEC_SCRIPT_UNKNOWN_INTF_ID;
        }
        break;
#endif
    }

exit:
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParsePropertyNameValuePair( const sbyte** pNextToken, const DynArray* pVars,
                            sbyte4 props[], IPSECCONF pIPSecConf)
{
    MSTATUS status = OK;
    ubyte4 data;
    sbyte4 token;
    CAST_MOC_IPADDR tunAddr;

    status = MatchToken( pNextToken, gPropertyTokens,
                            COUNTOF( gPropertyTokens), &token);

    if ( OK > status)
    {
        return ERR_IPSEC_SCRIPT_UNKNOWN_PROPERTY;
    }

    *pNextToken = GetNextToken(*pNextToken);
    switch (token)
    {
    case kAuthAlg:
        status = ParseAuthAlg( pNextToken, &data);
        if ( OK == status)
        {
            props[kAuthAlg] = data;
        }
        break;

    case kEncrAlg:
        status = ParseEncrAlg(pNextToken, &data);
        if (OK == status)
        {
            props[kEncrAlg] = data;
        }
        break;

    case kEncrAuthAlg:
        status = ParseAuthAlg( pNextToken, &data);
        if ( OK == status)
        {
            props[kEncrAuthAlg] = data;
        }
        break;

    case kTunnelSrc:
    case kTunnelDst:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte* ip6Addr = (ubyte*)(pIPSecConf + 1) + (16 * 4);
        if (kTunnelSrc == token) ip6Addr += 16;
#endif
        if ((props[token] != -1) ||
            (IPSEC_DIR_SOLARIS_9 & pIPSecConf->oDir))
        {
            status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
            break;
        }
        pIPSecConf->oDir |= IPSEC_DIR_SOLARIS_8;

        status = ParseAddress( pNextToken, pVars, &tunAddr
#ifdef __ENABLE_DIGICERT_IPV6__
                             , &ip6Addr
#endif
                              );
        if (OK == status)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (ip6Addr)
            {
                if (IPSEC_SP_FLAG_IP4_TUNNEL & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP6_TUNNEL;
            }
            else
            {
                if (IPSEC_SP_FLAG_IP6_TUNNEL & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP4_TUNNEL;
            }
#endif
            if (kTunnelDst == token)
                pIPSecConf->dwTunlDestIP = tunAddr;
            else
                pIPSecConf->dwTunlSrcIP = tunAddr;

            pIPSecConf->oMode = IPSEC_MODE_TUNNEL;
            props[token] = 0; /* !!! */
        }
        break;
    }
    case kTunnelRAddr:
    case kTunnelLAddr:
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte* ip6Addr = (ubyte*)(pIPSecConf + 1) + (16 * 4);
        if (kTunnelRAddr == token) ip6Addr += 16;
#endif
        if ((props[token] != -1) ||
            (IPSEC_DIR_SOLARIS_8 & pIPSecConf->oDir))
        {
            status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
            break;
        }
        pIPSecConf->oDir |= IPSEC_DIR_SOLARIS_9;

        status = ParseAddress( pNextToken, pVars, &tunAddr
#ifdef __ENABLE_DIGICERT_IPV6__
                             , &ip6Addr
#endif
                              );
        if (OK == status)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (ip6Addr)
            {
                if (IPSEC_SP_FLAG_IP4_TUNNEL & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP6_TUNNEL;
            }
            else
            {
                if (IPSEC_SP_FLAG_IP6_TUNNEL & pIPSecConf->flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    break;
                }
                pIPSecConf->flags |= IPSEC_SP_FLAG_IP4_TUNNEL;
            }
#endif
            if (kTunnelLAddr == token)
                pIPSecConf->dwTunlDestIP = tunAddr;
            else
                pIPSecConf->dwTunlSrcIP = tunAddr;

            pIPSecConf->oMode = IPSEC_MODE_TUNNEL;
            props[token] = 0; /* !!! */
        }
        break;
    }
    case kKeyLength:
        status = ParseNumber(pNextToken, pVars, props + kKeyLength);
        if ( OK > status)
        {
            props[kKeyLength] = -1; /* back */
        }
        else if ((0 > props[kKeyLength]) || (255 < props[kKeyLength]))
        {
            status = ERR_IPSEC_SCRIPT_BAD_KEY_LENGTH;
        }
        break;

    case kAeadTag:
        status = ParseNumber(pNextToken, pVars, props + kAeadTag);
        if ( OK > status)
        {
            props[kAeadTag] = -1; /* back */
        }
        else if ((0 > props[kAeadTag]) || (255 < props[kAeadTag]))
        {
            status = ERR_IPSEC_SCRIPT_BAD_TAG;
        }
        break;

    case kSaAttr:
        status = ParseSaAttr(pNextToken, &data);
        if (OK == status)
        {
            pIPSecConf->flags |= data;
        }
        break;

#ifdef __ENABLE_DIGICERT_IKE_SERVER__
    case kExpSecs:
        status = ParseNumber(pNextToken, pVars, (sbyte4 *)&data);
        if (OK == status)
        {
            pIPSecConf->dwSaSecs = data;
        }
        break;

    case kExpBytes:
        status = ParseNumber(pNextToken, pVars, (sbyte4 *)&data);
        if (OK == status)
        {
            pIPSecConf->dwSaBytes = data;
        }
        break;
#endif
    }

    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseAction( const sbyte** pCurrPos, IPSECCONF pIPSecConf)
{
    MSTATUS status = OK;
    ubyte4 data;

    *pCurrPos = GetNextToken(*pCurrPos);

    status = MatchToken( pCurrPos, gActionTokens,
                        COUNTOF(gActionTokens), (sbyte4*) &data);
    if ( OK > status)
    {
        status = ERR_IPSEC_SCRIPT_UNKNOWN_ACTION;
        goto exit;
    }

    if ((IPSEC_DIR_SOLARIS_9 & pIPSecConf->oDir) &&
        ((IPSEC_ACTION_APPLY == data) ||
         (IPSEC_DIR_OUTBOUND & pIPSecConf->oDir)))
    {
        /* swap dest. and src. */
        CAST_MOC_IPADDR dwIP;
        ubyte2 wPort;
        MCP_PORT_CONFIG_TYPE wPortType;

        dwIP = pIPSecConf->dwSrcIP;
        pIPSecConf->dwSrcIP = pIPSecConf->dwDestIP;
        pIPSecConf->dwDestIP = dwIP;

        dwIP = pIPSecConf->dwSrcIPEnd;
        pIPSecConf->dwSrcIPEnd = pIPSecConf->dwDestIPEnd;
        pIPSecConf->dwDestIPEnd = dwIP;

        wPort = pIPSecConf->wSrcPort;
        pIPSecConf->wSrcPort = pIPSecConf->wDestPort;
        pIPSecConf->wDestPort = wPort;

        if (MCP_SINGLE_PORT == pIPSecConf->srcPortType || MCP_SINGLE_PORT == pIPSecConf->destPortType) /*TODO: check if range check is requried in future*/
        {
            wPortType = pIPSecConf->destPortType;
            pIPSecConf->destPortType = pIPSecConf->srcPortType;
            pIPSecConf->srcPortType = wPortType;
        }

    }

    switch (data)
    {
    case IPSEC_ACTION_IPSEC :
        if (IPSEC_DIR_OUTBOUND & pIPSecConf->oDir)
        {
            data = IPSEC_ACTION_APPLY;
        }
        else if (IPSEC_DIR_INBOUND & pIPSecConf->oDir)
        {
            data = IPSEC_ACTION_PERMIT;
        }
        else if (IPSEC_DIR_SOLARIS_8 & pIPSecConf->oDir)
        {
            status = ERR_IPSEC_SCRIPT_UNKNOWN_DIRECTION;
            goto exit;
        }
        else
        {
            data = IPSEC_ACTION_PERMIT;
            pIPSecConf->oDir |= IPSEC_DIR_MIRRORED;
        }
        break;

    case IPSEC_ACTION_PERMIT :
        if (IPSEC_DIR_OUTBOUND & pIPSecConf->oDir)
        {
            status = ERR_IPSEC_SCRIPT_BAD_DIRECTION;
            goto exit;
        }
        break;

    case IPSEC_ACTION_APPLY :
        if (IPSEC_DIR_INBOUND & pIPSecConf->oDir)
        {
            status = ERR_IPSEC_SCRIPT_BAD_DIRECTION;
            goto exit;
        }
        break;

    default : /* bypass or drop */
        if (!((IPSEC_DIR_OUTBOUND|IPSEC_DIR_INBOUND) & pIPSecConf->oDir))
        {
            if (IPSEC_DIR_SOLARIS_8 & pIPSecConf->oDir)
            {
                status = ERR_IPSEC_SCRIPT_UNKNOWN_DIRECTION;
                goto exit;
            }
            else
            {
                pIPSecConf->oDir |= (IPSEC_DIR_INBOUND|IPSEC_DIR_MIRRORED);
            }
        }
        break;
    }

    pIPSecConf->oAction = (ubyte) data;

    /* filter out oDir for IPSEC_ACTION_APPLY and IPSEC_ACTION_PERMIT */
    if  (IPSEC_ACTION_APPLY == data || IPSEC_ACTION_PERMIT == data)
    {
        pIPSecConf->oDir &= IPSEC_DIR_MIRRORED;
    }

exit:
    return status;
}


/*------------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
MOC_EXTERN MSTATUS
validateSecurityPolicy(struct ipsecKeyEx *keyEx)
{
    MSTATUS status = OK;
    ubyte4 index = 0;
    intBoolean isEntryFound = FALSE;

    for (index = 0; index < activeGroupAddressIndex; index++)
    {
        /* Assuming if dwDestIP is same, dwDestIPEnd is also same or if the FQDN name is same */
        if (('\0' != keyEx->fqdn[0] && 0 == DIGI_STRCMP((sbyte *)m_activeGroupAddress[index].fqdn,(sbyte *) keyEx->fqdn)) ||
            ('\0' == keyEx->fqdn[0] && (m_activeGroupAddress[index].dwDestIP == keyEx->dwDestIP)))
        {
            isEntryFound = TRUE;
            if (m_activeGroupAddress[index].pxSa[0].oEncrAlgo && (m_activeGroupAddress[index].pxSa[0].oEncrAlgo != keyEx->oEncrAlgo))
            {
                status = ERR_IPSECCONF_ENCR_ALGO;
                break;
            }
            else if (m_activeGroupAddress[index].pxSa[0].oAuthAlgo && (m_activeGroupAddress[index].pxSa[0].oAuthAlgo != keyEx->oAuthAlgo))
            {
                status = ERR_IPSECCONF_AUTH_ALGO;
                break;
            }
            else if (m_activeGroupAddress[index].pxSa[0].aeadTag && (m_activeGroupAddress[index].pxSa[0].aeadTag != keyEx->oAeadIcvLen))
            {
                status = ERR_IPSECCONF_ICV;
                break;
            }
            else if (m_activeGroupAddress[index].pxSa[0].oEncrKeyLen && (m_activeGroupAddress[index].pxSa[0].oEncrKeyLen != keyEx->wEncrKeyLen - keyEx->oNonceLen))
            {
                status = ERR_IPSECCONF_KEY_LEN;
                break;
            }
            else if (keyEx->oProtocol == IPPROTO_AH)
            {
                if (m_activeGroupAddress[index].pxSa[0].oSecuProto != IPSEC_PROTO_AH)
                {
                    status = ERR_IPSECCONF_PROTOCOL;
                    break;
                }
            }
            else if (keyEx->oProtocol == IPPROTO_ESP)
            {
                if (m_activeGroupAddress[index].pxSa[0].oSecuProto != IPSEC_PROTO_ESP_AUTH)
                {
                    status = ERR_IPSECCONF_PROTOCOL;
                    break;
                }
            }
            break; /* No mismatch found */
        }
    }

    if (!isEntryFound)
    {
        status = ERR_IPSECCONF_INDEX;
    }
    return status;
}

/*------------------------------------------------------------------------*/
static MSTATUS
validateAgentPolicy(IPSECCONF pIPSecConf)
{
    MSTATUS status = OK, status1 = -1;
    ubyte4 i = 0;

    if (!pIPSecConf->oAction) /* Action not defined */
    {
        status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }
    /* Validate FQDN approach if Unicast GDOI is enabled */
    if (pIPSecConf->isUnicastGDOI)
    {
        if(!(pIPSecConf->flags ^ IPSEC_SP_FLAG_INIT)) /* Also has "sa init" */
        {
            if (activeGroupAddressIndex >= MAX_GROUP_NEGOTIATION)
            {
                status = ERR_IPSEC_SCRIPT_UNEXPECTED_EOF;
                goto exit;
            }
            m_activeGroupAddress[activeGroupAddressIndex] = *pIPSecConf;
            m_activeGroupAddress[activeGroupAddressIndex].pxSa = &pSAInfo[activeGroupAddressIndex];
            *(m_activeGroupAddress[activeGroupAddressIndex].pxSa) = *(pIPSecConf->pxSa);
            activeGroupAddressIndex++;
        }
    }
    else if (pIPSecConf->isGdoi)
    {
        MOC_IP_ADDRESS hostIp = 0;

        if (NULL != hostAddr)
        {
            int ip_count = 0;
            for(ip_count = 0; ip_count < MAX_HOST_IP; ip_count++)
            {
                if(NULL == hostAddr[ip_count])
                {
                    status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
                    break;
                }
                RemoveDotIP4Addr(hostAddr[ip_count], &hostIp);
                status = CheckIpInUnicastRange(REF_MOC_IPADDR(pIPSecConf->dwDestIP),
                    REF_MOC_IPADDR(pIPSecConf->dwDestIPEnd),
                    REF_MOC_IPADDR(hostIp), 0);
                if (IPSEC_ACTION_DROP == pIPSecConf->oAction)
                {
                    status1 = CheckIpInUnicastRange(REF_MOC_IPADDR(pIPSecConf->dwSrcIP),
                            REF_MOC_IPADDR(pIPSecConf->dwSrcIPEnd),
                            REF_MOC_IPADDR(hostIp), 0);
                }
                if (OK == status || OK == status1)
                {
                    status = OK;
                    break;
                }
            }
            if (OK > status)
            {
                DEBUG_PRINT(DEBUG_CUSTOM, (sbyte *)"\nInvalid configuration, Host IP not found in "
                    "Unicast range");
                status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
                goto exit;
            }
        }

        if(!(pIPSecConf->flags ^ IPSEC_SP_FLAG_INIT)) /* Also has "sa init" */
        {
            if (activeGroupAddressIndex >= MAX_GROUP_NEGOTIATION)
            {
                status = ERR_IPSEC_SCRIPT_UNEXPECTED_EOF;
                goto exit;
            }
            m_activeGroupAddress[activeGroupAddressIndex] = *pIPSecConf;
            m_activeGroupAddress[activeGroupAddressIndex].pxSa = &pSAInfo[activeGroupAddressIndex];
            *(m_activeGroupAddress[activeGroupAddressIndex].pxSa) = *(pIPSecConf->pxSa);
            activeGroupAddressIndex++;
        }
    }
    else if (pIPSecConf->dwDestIP || pIPSecConf->dwSrcIP) /* Policy has multicast group IP */
    {
        if(!(pIPSecConf->flags ^ IPSEC_SP_FLAG_INIT)) /* Also has "sa init" */
        {
            /* Check IP entry in m_activeGroupAddress */
            for(i = 0; i < activeGroupAddressIndex; i++)
            {
                if (pIPSecConf->dwDestIP == m_activeGroupAddress[i].dwDestIP)
                {
                    status = ERR_IPSEC_SCRIPT_DUPLICATE_DEF;
                    goto exit;
                }
            }
            if (activeGroupAddressIndex >= MAX_GROUP_NEGOTIATION)
            {
                status = ERR_IPSEC_SCRIPT_UNEXPECTED_EOF;
                goto exit;
            }
            m_activeGroupAddress[activeGroupAddressIndex] = *pIPSecConf;
            m_activeGroupAddress[activeGroupAddressIndex].pxSa = &pSAInfo[activeGroupAddressIndex];
            *(m_activeGroupAddress[activeGroupAddressIndex].pxSa) = *(pIPSecConf->pxSa);
            activeGroupAddressIndex++;
        }
    }
    else /* Policy does not have FQDN enabled or multicast/Unicast group IP*/
    {
        status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
    }

    if (MAX_GROUP_NEGOTIATION < activeGroupAddressIndex) /* Entries more than MAX_MULTICAST_GROUP */
    {
        status = ERR_IPSEC_SCRIPT_UNEXPECTED_EOF;
        goto exit;
    }

exit:
    return status;
}
#endif
#endif

/*------------------------------------------------------------------------*/

static MSTATUS
ParsePattern( const sbyte** pCurrPos, const DynArray* pVars, IPSECCONF pIPSecConf)
{
    MSTATUS status = OK;
    const sbyte* s;

    s = GetNextToken( *pCurrPos);

    if (*s != '{')
    {
        status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }
    ++s; /* over the { */

    while ( OK == status)
    {
        s = GetNextToken( s);
        if (0 == *s)
        {
            status = ERR_IPSEC_SCRIPT_UNEXPECTED_EOF;
            break;
        }
        if ('}' == *s)
        {
            ++s; /* jump over it */
            break;
        }
        status = ParsePatternNameValuePair( &s, pVars, pIPSecConf);
    }

exit:
    *pCurrPos = s;
    return status;
}

/*------------------------------------------------------------------------*/

static void
SetEncrAlgo(struct sainfo* pSAInfo,  sbyte4 encrAlgo, sbyte4 keyLen, sbyte4 aeadTag)
{
    pSAInfo->oEncrAlgo = (ubyte)encrAlgo;
    pSAInfo->oEncrKeyLen = (ubyte)((-1 != keyLen)? keyLen : 0);
    pSAInfo->aeadTag = (ubyte)((-1 != aeadTag)? aeadTag : 0);
}

/*------------------------------------------------------------------------*/

static MSTATUS
SetProperties(IPSECCONF pIPSecConf, sbyte4 props[])
{
    sbyte4 confType = 0;
    ubyte4 i;

#ifdef __ENABLE_DIGICERT_IPV6__
    pIPSecConf->flags &= ~(IPSEC_SP_FLAG_IP4 | IPSEC_SP_FLAG_IP4_TUNNEL);
#endif

    if (props[kTunnelRAddr] != -1 ||
        props[kTunnelLAddr] != -1)
    {
        if (IPSEC_ACTION_APPLY == pIPSecConf->oAction)
        {
            CAST_MOC_IPADDR dwIP = pIPSecConf->dwTunlSrcIP;
            pIPSecConf->dwTunlSrcIP = pIPSecConf->dwTunlDestIP;
            pIPSecConf->dwTunlDestIP = dwIP;
        }
    }

    /* we need to set the pPISecConf properly using
    a complicated set of rules */
    /* build a simple constant that represents all
    8 possibilities (tunnelDest, tunnelSrc, keyLength are not considered ) */
    for ( i = 0; i < 3; ++i)
    {
        if (props[i] != -1)
        {
            confType |= ( 1 << i);
        }
    }

    switch ( confType)
    {
    case 0:
        return ERR_IPSEC_SCRIPT_NO_PROPERTIES;

    case (1 << kAuthAlg): /* auth */
        pIPSecConf->oSaLen = 1;
        pIPSecConf->pxSa[0].oSecuProto = (ubyte) IPSEC_PROTO_AH;
        pIPSecConf->pxSa[0].oAuthAlgo = (ubyte) props[kAuthAlg];
        break;

    case (1 << kEncrAlg): /* encr */
        pIPSecConf->oSaLen = 1;
        pIPSecConf->pxSa[0].oSecuProto = (ubyte) IPSEC_PROTO_ESP;
        SetEncrAlgo(pIPSecConf->pxSa, props[kEncrAlg], props[kKeyLength], props[kAeadTag]);
        break;

    case ( 1<< kEncrAuthAlg): /* encrauth */
        pIPSecConf->oSaLen = 1;
        pIPSecConf->pxSa[0].oSecuProto = (ubyte) IPSEC_PROTO_ESP_NULL;
        pIPSecConf->pxSa[0].oAuthAlgo = (ubyte) props[kEncrAuthAlg];
        break;

    case ( (1 << kAuthAlg) | (1 << kEncrAlg)): /* auth + encr */
        pIPSecConf->oSaLen = 2;
        pIPSecConf->pxSa[0].oSecuProto = (ubyte) IPSEC_PROTO_ESP;
        SetEncrAlgo(pIPSecConf->pxSa, props[kEncrAlg], props[kKeyLength], props[kAeadTag]);
        pIPSecConf->pxSa[1].oSecuProto = (ubyte) IPSEC_PROTO_AH;
        pIPSecConf->pxSa[1].oAuthAlgo = (ubyte) props[kAuthAlg];
        break;

    case ( (1 << kAuthAlg) | (1 << kEncrAuthAlg)): /* auth + encrauth */
        pIPSecConf->oSaLen = 2;
        pIPSecConf->pxSa[0].oSecuProto = (ubyte) IPSEC_PROTO_ESP_NULL;
        pIPSecConf->pxSa[0].oAuthAlgo = (ubyte) props[kEncrAuthAlg];
        pIPSecConf->pxSa[1].oSecuProto = (ubyte) IPSEC_PROTO_AH;
        pIPSecConf->pxSa[1].oAuthAlgo = (ubyte) props[kAuthAlg];
        break;

    case ( (1 << kEncrAlg) | (1 << kEncrAuthAlg)): /* encr + encrauth */
        pIPSecConf->oSaLen = 1;
        pIPSecConf->pxSa[0].oSecuProto = (ubyte) IPSEC_PROTO_ESP_AUTH;
        pIPSecConf->pxSa[0].oAuthAlgo = (ubyte) props[kEncrAuthAlg];
        SetEncrAlgo(pIPSecConf->pxSa, props[kEncrAlg], props[kKeyLength], props[kAeadTag]);
        break;

    case ( (1 << kAuthAlg) | (1 << kEncrAlg) | (1 << kEncrAuthAlg)): /* auth + encr + encrauth */
        pIPSecConf->oSaLen = 2;
        pIPSecConf->pxSa[0].oSecuProto = (ubyte) IPSEC_PROTO_ESP_AUTH;
        pIPSecConf->pxSa[0].oAuthAlgo = (ubyte) props[kEncrAuthAlg];
        SetEncrAlgo(pIPSecConf->pxSa, props[kEncrAlg], props[kKeyLength], props[kAeadTag]);
        pIPSecConf->pxSa[1].oSecuProto = (ubyte) IPSEC_PROTO_AH;
        pIPSecConf->pxSa[1].oAuthAlgo = (ubyte) props[kAuthAlg];
        break;
    }

    return OK;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseProperties( const sbyte** pCurrPos, const DynArray* pVars, IPSECCONF pIPSecConf)
{
    MSTATUS status = OK;
    const sbyte* s;
    sbyte4 props[COUNTOF(gPropertyTokens)];
    ubyte4 i;

    /* always initialize to -1 (cf SetProperties) */
    for (i = 0; i < COUNTOF(gPropertyTokens); ++i)
    {
        props[i] = -1;
    }

    s = GetNextToken( *pCurrPos);

    if (*s != '{')
    {
        status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }
    ++s; /* over the { */

    while ( OK == status)
    {
        s = GetNextToken( s);
        if (0 == *s)
        {
            status = ERR_IPSEC_SCRIPT_UNEXPECTED_EOF;
            break;
        }
        if ('}' == *s)
        {
            ++s;
            break;
        }
        status = ParsePropertyNameValuePair( &s, pVars, props, pIPSecConf);
    }

    /* set the IPSECCONF with the values */
    if ( OK == status)
    {
        SetProperties( pIPSecConf, props);
    }

exit:
    *pCurrPos = s;
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseConstantDef( const sbyte** pCurrPos, DynArray* pVars)
{
    MSTATUS status = OK;
    Token newToken;
    const sbyte* s;

    /* get two strings, first must be a name, second a number or IP address */
    s = GetNextToken( *pCurrPos);
    newToken.m_str = s;
    newToken.m_len = GetNameLength(s);
    newToken.m_extra = 0;

    s+= newToken.m_len;

    s = GetNextToken(s);

    /* we are ok if there is no constants defined -> default to 0 */
    if ( ']' != *s)
    {
        /* try an IP address, if not try a simple number */
        status = ParseIP4Address( &s, (ubyte4 *)&newToken.m_extra);
        if (OK > status)
        {
            status = ReadNumber( &s, &newToken.m_extra);
        }
    }

    if (OK == status)
    {
        /* verify not duplicate definition */
        sbyte4 prevVal;
        const sbyte* testS = newToken.m_str;
        MSTATUS testStatus = MatchVariable( &testS, pVars, &prevVal);
        if ( OK == testStatus) /* duplicate */
        {
            /* only an error if values are different */
            if ( prevVal != newToken.m_extra)
            {
                status = ERR_IPSEC_SCRIPT_DUPLICATE_DEF;
            }
        }
        else
        {
            DYNARR_Append( pVars, &newToken);
        }
    }

    *pCurrPos = s;
    return status;
}

/*------------------------------------------------------------------------*/

static MSTATUS
ParseConstants( const sbyte** pCurrPos, DynArray* pVars)
{
    MSTATUS status = OK;
    const sbyte* s;

    s = GetNextToken( *pCurrPos);

    if (*s != '[')
    {
        status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }
    ++s; /* over the [ */

    while ( OK == status)
    {
        s = GetNextToken( s);
        if (0 == *s)
        {
            status = ERR_IPSEC_SCRIPT_UNEXPECTED_EOF;
            break;
        }
        if (']' == *s)
        {
            ++s; /* jump over it */
            break;
        }
        status = ParseConstantDef( &s, pVars);
    }

exit:
    *pCurrPos = s;
    return status;
}


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
extern intBoolean DIGI_find_fqdn(MOC_IP_ADDRESS ipAddr, char * fqdn)
{
    intBoolean isIpFound = FALSE;

    ubyte4 ipListIndex=0, fqdnListIndex=0;

    while(fqdnListIndex < m_groupListCount)
    {
        /* transverse the complete fqdn list to match if ip address is part of fqdn group list or not*/
        MOC_IS_IP_PART_OF_GROUP(ipAddr, m_fqdnGroupList[fqdnListIndex].fqdnName , isIpFound)
        if(isIpFound)
        {
            return TRUE;
        }
    }
    return FALSE;
}


extern sbyte4
#if !(defined(__ENABLE_DIGICERT_64_BIT__) && defined(__ENABLE_DIGICERT_IPV6__))
addIpListInGroup(char* fqdnName, ubyte4 ipList[], ubyte4* ipCount)
#else
addIpListInGroup(char* fqdnName, ubyte8 ipList[], ubyte4* ipCount)
#endif
{
    ubyte4 hostIpIndex = 0;
    ubyte4 count = 0, fqdnGroupIndex = 0;
    sbyte isFqdnFound = FALSE;
    byteBoolean is_host = FALSE;

    MOC_GROUP_FIND_FQDN(fqdnName, fqdnGroupIndex, isFqdnFound);
    if (TRUE == isFqdnFound)
    {
        while(count < m_fqdnGroupList[fqdnGroupIndex].ipListCount)
        {
            is_host = FALSE;
            hostIpIndex = 0;
            while(hostIpIndex < m_fqdnGroupList[fqdnListIndex].hostIPCount)
            {
               if (m_fqdnGroupList[fqdnListIndex].hostIp[hostIpIndex] == MOC_FQDN_IP_ADDR(fqdnGroupIndex, count))
               {
                   is_host = TRUE;
                   break;
               }
               hostIpIndex++;
            }
            if (!is_host)
            {
                ipList[*ipCount] = MOC_FQDN_IP_ADDR(fqdnGroupIndex, count);
                (*ipCount)++;
            }
            count++;
        }
    }
    else
    {
        DB_PRINT("Configuration Error: No fqdn entry found for configured fqdn:[%s]", fqdnName);
        return ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
    }
    return fqdnGroupIndex;
} /* addIpListInGroup */
#endif

/*------------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
static MSTATUS
addUnicastRangeAddr(IPSECCONF pxConf)
{
    MSTATUS status = OK;

    if (NULL == pxConf)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (pxConf->isGdoi)
    {
        if (!(pxConf->flags ^ IPSEC_SP_FLAG_INIT))
        {
            COPY_MOC_IPADDR(m_startRangeIP[m_rangeCount], pxConf->dwDestIP);
            COPY_MOC_IPADDR(m_endRangeIP[m_rangeCount], pxConf->dwDestIPEnd);
            m_rangeCount++;
        }
    }

exit:
	return status;
} /* addUnicastRangeAddr */
#endif


/*------------------------------------------------------------------------*/

static MSTATUS
ParsePolicy( const sbyte** pScriptContent, const DynArray* pDynArray,ubyte parse_only)
{
    MSTATUS status;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    ubyte4 hostIpIndex = 0;
    sbyte4 fqdnGroupIndex = 0;
#endif
    struct sainfo pSAInfo[2] = {{0}};

#ifndef __ENABLE_DIGICERT_IPV6__
    struct ipsecConf newConf = {0};
    IPSECCONF pIPSecConf = &newConf;
#else
    ubyte newConf[sizeof(struct ipsecConf) + (16 * 6)] = {0};
    IPSECCONF pIPSecConf = (IPSECCONF)newConf;
#endif
    pIPSecConf->pxSa = pSAInfo;

    status = ParsePattern(pScriptContent, pDynArray, pIPSecConf);
    if ( OK == status)
    {
        status = ParseAction(pScriptContent, pIPSecConf);
    }
    if (OK == status)
    {
        status = ParseProperties(pScriptContent, pDynArray, pIPSecConf);
    }

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__

    if(pIPSecConf->isUnicastGDOI && parse_only && ((pIPSecConf->flags & IPSEC_SP_FLAG_INIT)|| IPSEC_ACTION_DROP == pIPSecConf->oAction)) /* if its a unicast list grouping and first policy entry*/
    {
        ubyte4 fqdnIndex = 0;
        ubyte isFqdnFound = FALSE;

        /* Traverse the existing FQDN list and check if it already exists */
        while(fqdnIndex < m_groupListCount)
        {
            if(0 == DIGI_STRCMP((sbyte *)m_configured_fqdnList[fqdnIndex],(sbyte *)pIPSecConf->fqdn))
            {
                isFqdnFound = TRUE;
                status = ERR_IPSEC_SCRIPT_DUPLICATE_DEF;
                DB_PRINT("Configuration of FQDN group in policy file is duplicate");
                break;
            }
            fqdnIndex++;
        }

        if (FALSE == isFqdnFound)
        {
            DIGI_MEMCPY(m_configured_fqdnList[m_groupListCount], pIPSecConf->fqdn, MOC_MAX_FQDN_LEN);
            m_groupListCount++;
        }
    }
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    /* Store and start and end IP addresses for Unicast range */
    if (pIPSecConf->isGdoi && parse_only)
    {
        status = addUnicastRangeAddr(pIPSecConf);
    }
#endif
    if (parse_only)
    {
        return status;
    }

    /* Transverse the complete FQDN list and add IP address entries in the SPD for dropping traffic*/
    if (pIPSecConf->oAction == IPSEC_ACTION_DROP && pIPSecConf->isUnicastGDOI)
    {
        status = fqdnGroupIndex = addIpListInGroup(pIPSecConf->fqdn, pIPSecConf->dwSrcIPList, &pIPSecConf->dwSrcIPCount);
        if (fqdnGroupIndex >= 0)
        {
            status = OK;
        }
    }
    /* Transverse the complete FQDN list and add IP address entries in the SPD*/
    if(pIPSecConf->oAction == IPSEC_ACTION_APPLY && pIPSecConf->isUnicastGDOI)
    {
        status = fqdnGroupIndex = addIpListInGroup(pIPSecConf->fqdn, pIPSecConf->dwDestIPList, &pIPSecConf->dwDestIPCount);
        if(fqdnGroupIndex >= 0)
        {
            status = OK;
            while(hostIpIndex < m_fqdnGroupList[fqdnGroupIndex].hostIPCount)
            {
                pIPSecConf->dwSrcIPList[hostIpIndex] =  m_fqdnGroupList[fqdnGroupIndex].hostIp[hostIpIndex];
                pIPSecConf->dwSrcIPCount++;
                hostIpIndex++;
            }
        }
    }

    /* In case of action permit, traverse the FQDN list and update the source address */
    if(pIPSecConf->oAction == IPSEC_ACTION_PERMIT && pIPSecConf->isUnicastGDOI)
    {
        status = fqdnGroupIndex = addIpListInGroup(pIPSecConf->fqdn, pIPSecConf->dwSrcIPList, &pIPSecConf->dwSrcIPCount);
        if(fqdnGroupIndex >= 0)
        {
            status = OK;
            while(hostIpIndex < m_fqdnGroupList[fqdnGroupIndex].hostIPCount)
            {
                pIPSecConf->dwDestIPList[hostIpIndex] =  m_fqdnGroupList[fqdnGroupIndex].hostIp[hostIpIndex];
                pIPSecConf->dwDestIPCount++;
                hostIpIndex++;
            }
        }
    }
#endif

    if ( OK == status)
    {
        pIPSecConf->oDir &= ~(IPSEC_DIR_SOLARIS_8|IPSEC_DIR_SOLARIS_9);
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_DIGICERT_GDOI_SERVER__) && defined(__ENABLE_DIGICERT_MULTICAST_MCP__)
        /* Function to validate policy before applyling to the I/O driver */
        status = validateAgentPolicy(pIPSecConf);
#endif
        if ( OK == status)
        {
            status = (MSTATUS) IPSEC_confAdd1( pIPSecConf );
            /*status = ERR_IPSEC_SCRIPT;*/
        }
    }
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
Ascii2Hex( sbyte **s, sbyte4 len)
{
    MSTATUS status = OK;

    sbyte *dst;
    if (NULL == (dst = (sbyte *) MALLOC(2*len+1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
    }
    else
    {
        sbyte *src = *s;
        intBoolean inEsc = FALSE;

        sbyte4 i = 0;
        for (; 0 < len; len--, src++)
        {
            sbyte c = *src;

            if (inEsc) inEsc = FALSE;
            else if ( '\\' == c)
            {
                inEsc = TRUE;
                continue;
            }

            c = 0x0F & (c >> 4);
            if ( 9 < c) c += 'a' - 10;
            else c += '0';
            dst[i++] = c;

            c = 0x0F & (*src);
            if ( 9 < c) c += 'a' - 10;
            else c += '0';
            dst[i++] = c;
        }

        dst[i] = 0;
        *s = dst;
    }

    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
ParseAdd( sbyte4 argc, sbyte *argv[], const DynArray* pDynArray)
{
    MSTATUS status = OK;

    struct ipsecKey newKey = {0};

#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte ip6Addr[2][16];
#endif
    sbyte *s, *akey=NULL, *ekey=NULL;
    ubyte4 data;
    int i;

    int optind = 1;
    /*int optopt;*/
    sbyte *optarg;
    int c;

    for (i=0; (optind < argc) && (i < 4); optind++, i++)
    {
        s = argv[optind];
        switch (i)
        {
        case 0 : /* src */
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            ubyte* srcAddr6 = &(ip6Addr[1][0]);
#endif
            if (OK > (status = ParseAddress( (const sbyte **)&s, pDynArray,
                                             &newKey.dwSrcAddr
#ifdef __ENABLE_DIGICERT_IPV6__
                                           , &srcAddr6
#endif
                                            )))
                goto exit;
#ifdef __ENABLE_DIGICERT_IPV6__
            if (srcAddr6)
            {
                newKey.flags |= IPSEC_SA_FLAG_IP6;
            }
#endif
            break;
        }
        case 1 : /* dst */
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            ubyte* dstAddr6 = &(ip6Addr[0][0]);
#endif
            if (OK > (status = ParseAddress( (const sbyte **)&s, pDynArray,
                                             &newKey.dwDestAddr
#ifdef __ENABLE_DIGICERT_IPV6__
                                           , &dstAddr6
#endif
                                            )))
                goto exit;
#ifdef __ENABLE_DIGICERT_IPV6__
            if (dstAddr6)
            {
                if (!(IPSEC_SA_FLAG_IP6 & newKey.flags))
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    goto exit;
                }
            }
            else
            {
                if (IPSEC_SA_FLAG_IP6 & newKey.flags)
                {
                    status = ERR_IPSEC_SCRIPT_MIXED_AF_INET;
                    goto exit;
                }
            }
#endif
            break;
        }
        case 2 : /* protocol */
            if (OK > (status = ParseUlp((const sbyte **)&s, pDynArray, &data)))
                goto exit;
            newKey.oProtocol = (ubyte)data;
            break;
        case 3 : /* spi */
            if (OK > (status = ParseNumber((const sbyte **)&s, pDynArray, (sbyte4 *) &data)) ||
                (ubyte4)256 > data)
            {
                status = ERR_IPSEC_SCRIPT_BAD_SPI;
                goto exit;
            }
            newKey.dwSpi = data;
            break;
        }
    }
    if (4 != i)
    {
        status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
        goto exit;
    }

    for (; optind < argc; optind++)
    {
        optarg = argv[optind];

        if ('-' != optarg[0]) break;

        if (!optarg[1]) continue;

        if ('-' == (c = optarg[1]))
        {
            break;
        }

        /*optopt = c;*/
        if (((1+optind) >= argc) || ('-' == argv[1+optind][0]))
        {
            c = ':';
        }
        else
        {
            optarg = argv[++optind];
            s = (sbyte *)optarg;
        }

        switch (c)
        {
        case 'm' :
            if (OK > (status = MatchToken((const sbyte **)&s,
                                          gModeTokens,
                                          COUNTOF(gModeTokens),
                                          (sbyte4 *) &data)))
            {
                status = ERR_IPSEC_SCRIPT_UNKNOWN_MODE;
                goto exit;
            }
            newKey.oMode = (ubyte)data;
            break;

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        case 'l' : /* lifetime secs */
            if (OK > (status = ParseNumber((const sbyte **)&s, pDynArray, (sbyte4 *) &data)))
            {
                status = ERR_IPSEC_SCRIPT_BAD_LIFETIME;
                goto exit;
            }
            newKey.dwExpSecs = data;
            break;

        case 'b' : /* life kbytes - is this applicable? */
            if (OK > (status = ParseNumber((const sbyte **)&s, pDynArray, (sbyte4 *) &data)))
            {
                status = ERR_IPSEC_SCRIPT_BAD_LIFETIME;
                goto exit;
            }
            newKey.dwExpKBytes = data;
            break;
#endif
        case 'E' :
            if (newKey.oEncrAlgo) /* jic */
            {
                status = ERR_IPSEC_SCRIPT_DUPLICATE_DEF;
                goto exit;
            }

            if (OK > (status = MatchToken((const sbyte **)&s,
                                          gEncrAlgoTokens,
                                          COUNTOF(gEncrAlgoTokens),
                                          (sbyte4 *) &data)))
            {
                status = ERR_IPSEC_SCRIPT_UNKNOWN_EALGO;
                goto exit;
            }
            newKey.oEncrAlgo = (ubyte)data;

            if (((1+optind) >= argc) || ('-' == argv[1+optind][0]))
            {
                status = ERR_IPSEC_SCRIPT_BAD_EALGO_KEY;
                goto exit; /* missing key */
            }
            optarg = argv[++optind];

            s = (sbyte *)optarg;
            data = DIGI_STRLEN(s);
            if ( 0 == DIGI_STRNICMP( s, (sbyte *)"0x", 2))
            {
                newKey.pEncrKey = s + 2;
                newKey.wEncrKeyLen = (ubyte2)(data - 2);
            }
            else if ( ('"' == *s) && (1 < data) && ('"' == s[data-1]))
            {
                s++; data -= 2;
                if (OK > (status = Ascii2Hex(&s, (sbyte4)data))) goto exit;
                newKey.wEncrKeyLen = (ubyte2) DIGI_STRLEN(s);
                newKey.pEncrKey = s;
                ekey = s;
            }
            else
            {
                status = ERR_IPSEC_SCRIPT_BAD_EALGO_KEY;
                goto exit;
            }
            break;

        case 'A' :
            if (newKey.oAuthAlgo) /* jic */
            {
                status = ERR_IPSEC_SCRIPT_DUPLICATE_DEF;
                goto exit;
            }

            if (OK > (status = MatchToken((const sbyte **)&s,
                                          gAuthAlgoTokens,
                                          COUNTOF(gAuthAlgoTokens),
                                          (sbyte4 *) &data)))
            {
                status = ERR_IPSEC_SCRIPT_UNKNOWN_AALGO;
                goto exit;
            }
            newKey.oAuthAlgo = (ubyte)data;

            if (((1+optind) >= argc) || ('-' == argv[1+optind][0]))
            {
                status = ERR_IPSEC_SCRIPT_BAD_AALGO_KEY;
                goto exit; /* missing key */
            }
            optarg = argv[++optind];

            s = (sbyte *)optarg;
            data = DIGI_STRLEN(s);
            if ( 0 == DIGI_STRNICMP( s, (sbyte *)"0x", 2))
            {
                newKey.pAuthKey = s + 2;
                newKey.wAuthKeyLen = (ubyte2)(data - 2);
            }
            else if ( ('"' == *s) && (1 < data) && ('"' == s[data-1]))
            {
                s++; data -= 2;
                if (OK > (status = Ascii2Hex(&s, (sbyte4)data))) goto exit;
                newKey.wAuthKeyLen = (ubyte2) DIGI_STRLEN(s);
                newKey.pAuthKey = s;
                akey = s;
            }
            else
            {
                status = ERR_IPSEC_SCRIPT_BAD_AALGO_KEY;
                goto exit;
            }
            break;

        case ':' :   /* without operand */
            break;
        default :   /* invalid option */
            DB_PRINT("Invalid option -%c\n", c);
            break;
        }
    }

    if (!newKey.oEncrAlgo && !newKey.oAuthAlgo)
    {
        status = ERR_IPSEC_SCRIPT_NO_ALGOS;
        goto exit;
    }

    if (1 != (i = (int) IPSEC_keyAdd( &newKey, 1 )))
    {
        if (0 > i) status = (MSTATUS)i;
        else if (OK == (status = (MSTATUS) newKey.status))
            status = STATUS_IPSEC_KEYADD_ABORT;
    }

exit:
    if (akey) FREE(akey);
    if (ekey) FREE(ekey);
    return status;
}


/*------------------------------------------------------------------------*/

static const sbyte*
GetArg( const sbyte* s, sbyte4 *arglen)
{
    intBoolean inQuote = ( '"' == *s);
    intBoolean isOpt = ( '-' == *s);
    intBoolean inEsc = FALSE;

    if (inQuote || isOpt)
    {
        s++; (*arglen)++;
    }

    while (*s)
    {
        sbyte c = *s;

        if (inEsc) inEsc = FALSE;
        else if (inQuote && ( '\\' == c)) inEsc = TRUE;
        else if (inQuote && ( '"' == c))
        {
            s++; (*arglen)++;
            break;
        }
        else if (IsWhiteSpace(c) ||
                 ( ';' == c) ||  ( '"' == c) ||
                 ( '#' == c) || ( '[' == c) || ( '{' == c))
        {
            break;
        }

        s++; (*arglen)++;

        if (isOpt) break;
    }

    return s;
}


/*------------------------------------------------------------------------*/

#define CMD_ARG_MAX 32

static MSTATUS
ParseCommand( const sbyte** pScriptContent, const DynArray* pDynArray)
{
    MSTATUS status = OK;

    sbyte4 argc = 0;
    sbyte* argv[CMD_ARG_MAX] = { 0 };

    while (**pScriptContent)
    {
        sbyte4 arglen = 0;
        const sbyte *s = *pScriptContent;

        if (';' == *s) /* end of command */
        {
            (*pScriptContent)++;
            break;
        }

        if (CMD_ARG_MAX == argc)
        {
            /* too many arguments - probably missing ';' */
            status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
            goto exit;
        }

        *pScriptContent = GetArg(s, &arglen);

        if (NULL == (argv[argc] = (sbyte *) MALLOC(arglen+1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(argv[argc], s, arglen);
        argv[argc][arglen] = 0;
        argc++;

        *pScriptContent = GetNextToken(*pScriptContent);
    }

    if (argc)
    {
        sbyte4 cmd;
        const sbyte *s = argv[0];
        if ( OK > (status = MatchToken( &s,
                                gCommandTokens,
                                COUNTOF(gCommandTokens),
                                &cmd)))
        {
            status = ERR_IPSEC_SCRIPT_UNKNOWN_COMMAND;
            goto exit;
        }

        switch (cmd)
        {
        case kAdd :
            status = ParseAdd(argc, argv, pDynArray);
            break;
        case kFlush :
            status = (MSTATUS) IPSEC_keyFlush();
            break;
        case kSpdFlush :
            status = (MSTATUS) IPSEC_confFlush();
            break;
        default :
            status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
            break;
        }
    }

exit:
    while (argc) FREE(argv[--argc]);
    return status;
}


/*------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
IPSEC_ParseScript( const sbyte* scriptContent, ubyte parse_only, sbyte** hostIpAddr)
{
    DynArray dynArr;
    MSTATUS status = OK;

    if (OK > (status = DYNARR_Init( sizeof(Token), &dynArr)))
    {
        return status;
    }

    if (NULL != hostIpAddr)
    {
        hostAddr = hostIpAddr;
    }
    scriptContent = GetNextToken(scriptContent);
    while (OK == status && *scriptContent)
    {
        if ('{' == *scriptContent)
        {
            if (OK > (status = ParsePolicy(&scriptContent, &dynArr, parse_only)))
            {
                return status;
            }
        }
        else if ( '[' == *scriptContent)
        {
            status = ParseConstants(&scriptContent, &dynArr);
        }
        else
        {
            status = ParseCommand(&scriptContent, &dynArr);
            /*status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;*/
        }
        scriptContent = GetNextToken(scriptContent);
    }

    DYNARR_Uninit( &dynArr);

    return status;
}


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) || defined(__ENABLE_DIGICERT_IKE_SERVER__) */

