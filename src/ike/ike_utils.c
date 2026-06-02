/**
 * @file  ike_utils.c
 * @brief IKE utility functions.
 *
 * @details    IKE helper functions for message processing and debugging.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/ca_mgmt.h"
#include "../crypto/pubcrypto.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_protos.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_state.h"
#include "../ike/ikesa.h"
#include "../ike/ike_crypto.h"
#include "../ike/ike_cert.h"


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define _IN  1
#define _OUT 2


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getPsk(ubyte **ppoPsk, ubyte4 *pdwPskLen,
           IKESA pxSa,
           sbyte4 dir) /* [v1] 0=both, or [v2] 1=in/peer, 2=out/host */
{
    MSTATUS status;

    ubyte4 dwPskLen;

#ifdef CUSTOM_IKE_GET_PSK
    ubyte *poId = NULL; /* peer's ID */
    ubyte2 wIdLen = 0;
    sbyte4 idType = 0;

    intBoolean bInitiator = IS_INITIATOR(pxSa);
    struct ikeIdHdr *pxId = pxSa->pxID[bInitiator ? _R : _I];
    if (NULL != pxId)
    {
        wIdLen = GET_NTOHS(pxId->wLength) - (ubyte2)SIZEOF_IKE_ID_HDR;
        poId = ((ubyte *)pxId) + SIZEOF_IKE_ID_HDR;
        idType = pxId->oType;
    }
    dwPskLen = (ppoPsk ? IKE_PSK_MAX : 0);
    status = CUSTOM_IKE_GET_PSK((ppoPsk ? pxSa->ikePeerConfig->psk : NULL), &dwPskLen,
                                poId, wIdLen, idType,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                dir, bInitiator
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance));

    if (STATUS_IKE_CUSTOM_CONTINUE != status)
    {
        if (OK > status) goto exit;

        if (ppoPsk)
        {
            if (!dwPskLen)
            {
                status = ERR_IKE_NULL_PSK;
                goto exit;
            }
            *ppoPsk = pxSa->ikePeerConfig->psk;
        }
    }
    else
#else
    MOC_UNUSED(pxSa);
    MOC_UNUSED(dir);
#endif /* CUSTOM_IKE_GET_PSK */
    {
        status = OK;
        dwPskLen =(pxSa->ikePeerConfig->ikePSKey ? pxSa->ikePeerConfig->ikePSKeyLen : 0);

        if (!dwPskLen)
        {
            status = ERR_IKE_NULL_PSK;
            goto exit;
        }
        if (ppoPsk) *ppoPsk = pxSa->ikePeerConfig->ikePSKey;
    }

    if (pdwPskLen) *pdwPskLen = dwPskLen;

exit:
    return status;
} /* IKE_getPsk */


/*------------------------------------------------------------------*/

extern intBoolean
IKE_isEmptyCky(const ubyte cky[8]) /* IKE_COOKIE_SIZE */
{
    intBoolean ret = TRUE;

    sbyte i;
    for (i=0; i < 8/*IKE_COOKIE_SIZE*/; i++)
    {
        if (cky[i])
        {
            ret = FALSE;
            break;
        }
    }

    return ret;
} /* IKE_isEmptyCky */


/*------------------------------------------------------------------*/

extern void
IKE_scanHexKey(sbyte4 keyDataLen, const sbyte *poKeyData,
               sbyte4 keyLen, ubyte *poKey)
{
    sbyte4 i;

    DIGI_MEMSET(poKey, 0x00, keyLen);

    for (i=0; i < keyDataLen; i++)
    {
        ubyte c = (ubyte) poKeyData[i];
        sbyte4 j = i / 2;

        if (j >= keyLen) break;

        if (('0' <= c) && ('9' >= c))
        {
            c -= '0';
        }
        else if (('A' <= c) && ('F' >= c))
        {
            c -= 'A' - 10;
        }
        else if (('a' <= c) && ('f' >= c))
        {
            c -= 'a' - 10;
        }

        poKey[j] |= c << ((i % 2) ? 0 : 4);
    }
} /* IKE_scanHexKey */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_travAttrs(const ubyte *attrs, ubyte2 len, void *cb,
              MSTATUS(*funcPtrCallback)(void * /* cb */,
                        ubyte2 /* type */,
                        intBoolean /* Basic (TRUE) or Variable (FALSE) */,
                        ubyte2 /* value (B) or length (V)*/,
                        const ubyte * /* data {V} */))
{
    MSTATUS status = OK;

    if (NULL == attrs) /* jic */
    {
        status = ERR_NULL_POINTER;
    }
    else
    while (SIZEOF_IKE_CFG_ATTR_HDR <= len)
    {
        intBoolean bBasic;
        const ubyte *poData;
        ubyte2 wType, wLenOrVal;

        struct ikeCfgAttrHdr *pxCfgAttr = (struct ikeCfgAttrHdr *)attrs;
        len = len - (ubyte2)SIZEOF_IKE_CFG_ATTR_HDR;
        attrs += SIZEOF_IKE_CFG_ATTR_HDR;

        SET_NTOHS(wType, pxCfgAttr->wType);
        SET_NTOHS(wLenOrVal, pxCfgAttr->wLength);

        if (0x8000 & wType) /* basic */
        {
            bBasic = TRUE;
            wType &= 0x7fff;
            poData = attrs - 2;
        }
        else /* variable */
        {
            bBasic = FALSE;
            if (wLenOrVal > len)
            {
                status = ERR_IKE_BAD_LEN;
                break;
            }
            poData = attrs;
            attrs += wLenOrVal;
            len = len - wLenOrVal;
        }

        if (NULL != funcPtrCallback)
        {
            if (OK > (status = funcPtrCallback(cb, wType, bBasic,
                                               wLenOrVal, poData)))
                break;
        }
    } /* while */

    return status;
} /* IKE_travAttrs */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_travMsg(const ubyte *poMsg, ubyte4 dwLength, void *cb,
            MSTATUS(*funcPtrCallback)(void * /* cb */,
                                      ubyte /* payload type */,
                                      const ubyte * /* payload */,
                                      intBoolean * /* stop */))
{
    MSTATUS status = OK;

    intBoolean bStop = FALSE, bIke2 = FALSE;
    struct ikeHdr *pxHdr = (struct ikeHdr *)poMsg;
    ubyte oNextPayload;
    ubyte4 temp;

    if (NULL == poMsg) /* jic */
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (SIZEOF_ISAKMP_HDR > dwLength)
    {
        status = ERR_IKE_BAD_LEN;
        goto exit;
    }

    if ((2<<4) == pxHdr->oVersion) bIke2 = TRUE;
    else if ((1<<4) != pxHdr->oVersion)
    {
        status = ERR_IKE_BAD_VERSION;
        goto exit;
    }

    SET_NTOHL(temp, pxHdr->dwLength);
    if (SIZEOF_ISAKMP_HDR > temp)
    {
        status = ERR_IKE_BAD_LEN;
        goto exit;
    }

    if (!bIke2 && (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
    {
        /* [v1] do not traverse encrypted message */
        status = ERR_IKE_BAD_FLAGS;
        goto exit;
    }

    if (temp < dwLength) dwLength = temp;

    oNextPayload = pxHdr->oNextPayload;
    poMsg += SIZEOF_ISAKMP_HDR;
    dwLength -= SIZEOF_ISAKMP_HDR;

    while (dwLength && (ISAKMP_NEXT_NONE != oNextPayload))
    {
        struct ikeGenHdr *pxGenHdr = (struct ikeGenHdr *)poMsg;
        ubyte2 wLength;

        if (SIZEOF_IKE_GEN_HDR > dwLength)
        {
            status = ERR_IKE_BAD_LEN;
            goto exit;
        }

        SET_NTOHS(wLength, pxGenHdr->wLength);

        if ((SIZEOF_IKE_GEN_HDR > wLength) || ((ubyte4)wLength > dwLength))
        {
            status = ERR_IKE_BAD_LEN;
            goto exit;
        }

        if (NULL != funcPtrCallback)
        {
            if (OK > (status = funcPtrCallback(cb, oNextPayload, poMsg, &bStop)))
                break;

            if (bStop) break;
        }
        oNextPayload = pxGenHdr->oNextPayload;
        poMsg += wLength;
        dwLength -= (ubyte4)wLength;

    } /* while */

exit:
    return status;
} /* IKE_travMsg */

extern MSTATUS MCP_getFullPath(const sbyte *pDirPath, const sbyte *pCertName, ubyte **ppFullPath)
{
    MSTATUS status;
    ubyte4 slash = 0;
    ubyte4 dirPathLen;
    ubyte4 certNameLen;
    ubyte *pFullPath = NULL;
    if ((NULL == pDirPath) || (NULL == pCertName) || (NULL == ppFullPath))
        return ERR_NULL_POINTER;

    dirPathLen = DIGI_STRLEN(pDirPath);
    certNameLen = DIGI_STRLEN(pCertName);

    if ((0 < dirPathLen) && ('/' != pDirPath[dirPathLen - 1]))
        slash = 1;

    status = DIGI_MALLOC((void **) &pFullPath, dirPathLen + certNameLen + slash + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pFullPath, pDirPath, dirPathLen);
    if (OK != status)
        goto exit;

    if (slash)
        pFullPath[dirPathLen] = '/';

    status = DIGI_MEMCPY(pFullPath + dirPathLen + slash, pCertName, certNameLen);
    if (OK != status)
        goto exit;

    pFullPath[dirPathLen + certNameLen + slash] = 0;

    *ppFullPath = pFullPath;
    pFullPath = NULL;
exit:
    return status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)

extern void
debug_printr(const ubyte *data, sbyte4 len, intBoolean br)
{
    sbyte4 i;

    for (i=0; i < len; i++)
    {
        DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, data[i]);
        if (br)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
            if (len == (i+1)) break;
            if (15 == (i%16))
            {
                DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
            }
        }
    }

    if (br)
    {
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
    }
} /* debug_printr */


/*------------------------------------------------------------------*/

extern void
debug_printk(sbyte *label, const ubyte *data, ubyte2 len)
{
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, label);
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" (");
    DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)len);
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" bytes): ");
    debug_printr(data, (sbyte4)len, FALSE);
    DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
} /* debug_printk */


/*------------------------------------------------------------------*/

extern void
debug_printd(sbyte *label, const ubyte *data, ubyte2 len)
{
    if (NULL != label)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, label);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
    }
    debug_printr(data, (sbyte4)len, TRUE);
} /* debug_printd */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_payload(ubyte oPayload)
{
    sbyte *pStr;

    switch (oPayload)
    {
    /* [v1] */
    case ISAKMP_NEXT_NONE       : pStr = (sbyte *)"None"; break;
    case ISAKMP_NEXT_SA         : pStr = (sbyte *)"SA"; break;    /* Security Association */
    case ISAKMP_NEXT_P          : pStr = (sbyte *)"Prop"; break;  /* Proposal */
    case ISAKMP_NEXT_T          : pStr = (sbyte *)"Tfm"; break;   /* Transform */
    case ISAKMP_NEXT_KE         : pStr = (sbyte *)"KE"; break;    /* Key Exchange */
    case ISAKMP_NEXT_ID         : pStr = (sbyte *)"ID"; break;    /* Identification */
    case ISAKMP_NEXT_CERT       : pStr = (sbyte *)"CERT"; break;  /* Certificate */
    case ISAKMP_NEXT_CR         : pStr = (sbyte *)"CR"; break;    /* Certificate Request */
    case ISAKMP_NEXT_HASH       : pStr = (sbyte *)"HASH"; break;  /* Hash */
    case ISAKMP_NEXT_SIG        : pStr = (sbyte *)"SIG"; break;   /* Signature */
    case ISAKMP_NEXT_NONCE      : pStr = (sbyte *)"NONCE"; break; /* Nonce */
    case ISAKMP_NEXT_N          : pStr = (sbyte *)"Notify"; break;/* Notification */
    case ISAKMP_NEXT_D          : pStr = (sbyte *)"Delete"; break;/* Delete */
    case ISAKMP_NEXT_VID        : pStr = (sbyte *)"VID"; break;   /* Vendor ID */
    case ISAKMP_NEXT_ATTR       : pStr = (sbyte *)"ATTR"; break;  /* Mode config Attribute */
    case ISAKMP_NEXT_NAT_D      : pStr = (sbyte *)"NAT-D"; break; /* NAT Discovery */
    case ISAKMP_NEXT_NAT_OA     : pStr = (sbyte *)"NAT-OA"; break;/* NAT Original Address */

    /* [v2] */
/*  case IKE_NEXT_NONE          : pStr = (sbyte *)"None"; break;*/
    case IKE_NEXT_SA            : pStr = (sbyte *)"SA"; break;      /* Security Association */
    case IKE_NEXT_KE            : pStr = (sbyte *)"KE"; break;      /* Key Exchange */
    case IKE_NEXT_ID_I          : pStr = (sbyte *)"IDi"; break;     /* Identification - Initiator (IDi) */
    case IKE_NEXT_ID_R          : pStr = (sbyte *)"IDr"; break;     /* Identification - Responder (IDr) */
    case IKE_NEXT_CERT          : pStr = (sbyte *)"CERT"; break;    /* Certificate */
    case IKE_NEXT_CERTREQ       : pStr = (sbyte *)"CERTREQ"; break; /* Certificate Request */
    case IKE_NEXT_AUTH          : pStr = (sbyte *)"AUTH"; break;    /* Authentication */
    case IKE_NEXT_NONCE         : pStr = (sbyte *)"NONCE"; break;   /* Nonce (Ni, Nr) */
    case IKE_NEXT_N             : pStr = (sbyte *)"N"; break;       /* Notify */
    case IKE_NEXT_D             : pStr = (sbyte *)"D"; break;       /* Delete */
    case IKE_NEXT_V             : pStr = (sbyte *)"V"; break;       /* Vendor ID */
    case IKE_NEXT_TS_I          : pStr = (sbyte *)"TSi"; break;     /* Traffic Selector - Initiator (TSi) */
    case IKE_NEXT_TS_R          : pStr = (sbyte *)"TSr"; break;     /* Traffic Selector - Responder (TSr) */
    case IKE_NEXT_E             : pStr = (sbyte *)"E"; break;       /* Encrypted */
    case IKE_NEXT_CP            : pStr = (sbyte *)"CP"; break;      /* Configuration */
    case IKE_NEXT_EAP           : pStr = (sbyte *)"EAP"; break;     /* Extensible Authentication */
    case IKE_NEXT_EF            : pStr = (sbyte *)"EF"; break;      /* Encrypted Fragment */

    /* private */
    case ISAKMP_NEXT_FRAGMENT   : pStr = (sbyte *)"FGMT"; break;    /* IKE Fragmentation */

    default                     : pStr = NULL; break;
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)oPayload);
    }
} /* debug_print_ike_payload */


/*------------------------------------------------------------------*/

extern void
debug_print_ikehdr(ubyte *poHdr)
{
    struct ikeHdr *pxHdr = (struct ikeHdr *)poHdr;
    ubyte4 dwMsgId = GET_NTOHL(pxHdr->dwMsgId);
    ubyte oVersion = (pxHdr->oVersion >> 4);
    ubyte oFlags = pxHdr->oFlags;
    sbyte *pStr = NULL;

    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)((2 == oVersion)? " spi={" : " cookies={"));
    debug_printr(pxHdr->poCky_I, 8/*IKE_COOKIE_SIZE*/, FALSE);
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
    debug_printr(pxHdr->poCky_R, 8/*IKE_COOKIE_SIZE*/, FALSE);
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'}');

    /* [v2] */
    if (IKE_FLAG_INITIATOR & oFlags)
    {
/*      DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'R');*/
        oFlags &= ~(IKE_FLAG_INITIATOR);
    }

    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" np=");
    debug_print_ike_payload(pxHdr->oNextPayload);
    if (IKE_NEXT_E == pxHdr->oNextPayload)
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'{');
        debug_print_ike_payload(((struct ikeGenHdr *)(poHdr + SIZEOF_ISAKMP_HDR))->oNextPayload);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'}');
    }
#ifdef __ENABLE_IKE_FRAGMENTATION__
    else if (IKE_NEXT_EF == pxHdr->oNextPayload)
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'{');
        struct ike2FragHdr *pxSkfHdr = (struct ike2FragHdr *)(poHdr + SIZEOF_ISAKMP_HDR);
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) GET_NTOHS(pxSkfHdr->wFragNum));
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'/');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) GET_NTOHS(pxSkfHdr->wTotalFragments));
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
        debug_print_ike_payload(pxSkfHdr->oNextPayload);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'}');
    }
#endif
    DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");

    if ((2 != oVersion) && (1 != oVersion))
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" ver=");
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)oVersion);
    }

    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" exchange=");
    switch (pxHdr->oExchange)
    {
    /* [v1] */
    case ISAKMP_XCHG_IDPROT     : pStr = (sbyte *)"Main";   break;
    case ISAKMP_XCHG_AGGR       : pStr = (sbyte *)"Aggr";   break;
    case ISAKMP_XCHG_INFO       : pStr = (sbyte *)"Info";   break;
    case ISAKMP_XCHG_CFG        : pStr = (sbyte *)"Cfg";    break;
    case ISAKMP_XCHG_QUICK      : pStr = (sbyte *)"Quick";  break;
    /* [v2] */
    case IKE_XCHG_INIT          : if (2 == oVersion)
                                  pStr = (sbyte *)"IKE_SA_INIT";
                                  break;
    case IKE_XCHG_AUTH          : pStr = (sbyte *)"IKE_AUTH";           break;
    case IKE_XCHG_CHILD         : pStr = (sbyte *)"CREATE_CHILD_SA";    break;
    case IKE_XCHG_INFO          : pStr = (sbyte *)"INFORMATIONAL";      break;

    default                     : break;
    }
    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) pxHdr->oExchange);
    }

    if (0 != oFlags)
    {
        /* [v1] */
        if (ISAKMP_FLAG_ENCRYPTION & oFlags)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'*');
            oFlags &= ~(ISAKMP_FLAG_ENCRYPTION);
        }
        if (ISAKMP_FLAG_COMMIT & oFlags)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" commmit");
            oFlags &= ~(ISAKMP_FLAG_COMMIT);
        }
        if (ISAKMP_FLAG_AUTH_ONLY & oFlags)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" auth");
            oFlags &= ~(ISAKMP_FLAG_AUTH_ONLY);
        }

        /* [v2] */
        if (IKE_FLAG_RESPONSE & oFlags)
        {
/*          DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'<');*/
            oFlags &= ~(IKE_FLAG_RESPONSE);
        }
        if (IKE_FLAG_VERSION & oFlags)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" version");
            oFlags &= ~(IKE_FLAG_VERSION);
        }

        if (0 != oFlags)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" (flags=");
            DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) pxHdr->oFlags);
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)')');
        }
    }

    if (dwMsgId || (2 == oVersion))
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" msgid=");
        if (2 == oVersion)
        {
            DEBUG_UINT(DEBUG_IKE_MESSAGES, dwMsgId);
        }
        else
        {
            DEBUG_HEXINT(DEBUG_IKE_MESSAGES, (sbyte4)dwMsgId);
        }
    }

    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" len=");
    DEBUG_UINT(DEBUG_IKE_MESSAGES, (sbyte4) GET_NTOHL(pxHdr->dwLength));

    DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
} /* debug_print_ikehdr */


/*------------------------------------------------------------------*/

static void
debug_print_ip4(ubyte4 dwIpAddr)
{
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
    DEBUG_INT(DEBUG_IKE_MESSAGES, (dwIpAddr >> 24));
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'.');
    DEBUG_INT(DEBUG_IKE_MESSAGES, ((dwIpAddr & 0x00ff0000) >> 16));
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'.');
    DEBUG_INT(DEBUG_IKE_MESSAGES, ((dwIpAddr & 0x0000ff00) >> 8));
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'.');
    DEBUG_INT(DEBUG_IKE_MESSAGES, (dwIpAddr & 0x000000ff));
#endif
} /* debug_print_ip4 */


/*------------------------------------------------------------------*/

static void
debug_print_ip6(const ubyte *in_addr6)
{
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
    sbyte4 i, zeros=0;
    for (i=0; i < 16; i += 2)
    {
        if (i && (0 >= zeros))
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)':');
        }

        if (in_addr6[i])
        {
            if (0 < zeros) zeros = -1;
            DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, (sbyte)in_addr6[i]);
            DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, (sbyte)in_addr6[i+1]);
        }
        else if (in_addr6[i+1])
        {
            if (0 < zeros) zeros = -1;
            DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, (sbyte)in_addr6[i+1]);
        }
        else if (i && (0 > zeros) && (14 > i))
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'0');
        }
        else if (i && (0 <= zeros))
        {
            if ((0 == zeros++) && (14 > i))
            {
                DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)':');
            }
        }
    }
#endif
} /* debug_print_ip6 */


/*------------------------------------------------------------------*/

extern void
debug_print_ip(MOC_IP_ADDRESS ipAddr)
{
    TEST_MOC_IPADDR6(ipAddr,
    {
        debug_print_ip6(GET_MOC_IPADDR6(ipAddr));
        if (ipAddr->uin.addr6[4])
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'%');
            DEBUG_UINT(DEBUG_IKE_MESSAGES, (sbyte4) ipAddr->uin.addr6[4]);
        }
    })
        debug_print_ip4(GET_MOC_IPADDR4(ipAddr));
} /* debug_print_ip */


/*------------------------------------------------------------------*/

extern void
debug_print_ip_proto(ubyte oProto)
{
    sbyte *pStr;

    switch (oProto)
    {
    case IPPROTO_IPIP   : pStr = (sbyte *)"ipip";   break;
    case IPPROTO_TCP    : pStr = (sbyte *)"tcp";    break;
    case IPPROTO_UDP    : pStr = (sbyte *)"udp";    break;
    case IPPROTO_ICMP   : pStr = (sbyte *)"icmp";   break;
    case IPPROTO_ESP    : pStr = (sbyte *)"esp";    break;
    case IPPROTO_AH     : pStr = (sbyte *)"ah";     break;
    case IPPROTO_ICMPV6 : pStr = (sbyte *)"icmp6";  break;
    default             : pStr = NULL;              break;
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)oProto);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
    }
} /* debug_print_ip_proto */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_proto(ubyte oProtoId)
{
    sbyte *pStr = NULL;

    switch (oProtoId)
    {
    case PROTO_ISAKMP   : pStr = (sbyte *)"IKE";    break;
    case PROTO_IPSEC_AH : pStr = (sbyte *)"AH";     break;
    case PROTO_IPSEC_ESP: pStr = (sbyte *)"ESP";    break;
#ifdef __ENABLE_DIGICERT_IPCOMP__
    case PROTO_IPCOMP   : pStr = (sbyte *)"IPCOMP"; break;
#endif
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)oProtoId);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
    }
} /* debug_print_ike_proto */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_tfmid(ubyte oAttrId, ubyte oProtoId)
{
    sbyte *pStr = NULL;

    switch (oProtoId)
    {
    case PROTO_ISAKMP   :
        switch (oAttrId)
        {
        case KEY_IKE        : pStr = (sbyte *)"KEY-IKE";        break;
        }
        break;
    case PROTO_IPSEC_AH :
        switch (oAttrId)
        {
        case AH_MD5         : pStr = (sbyte *)"AH-MD5";         break;
        case AH_SHA         : pStr = (sbyte *)"AH-SHA";         break;
        case AH_SHA2_256    : pStr = (sbyte *)"AH-SHA2-256";    break;
        case AH_SHA2_384    : pStr = (sbyte *)"AH-SHA2-384";    break;
        case AH_SHA2_512    : pStr = (sbyte *)"AH-SHA2-512";    break;
        case AH_AES_XCBC    : pStr = (sbyte *)"AH-AES-XCBC";    break;
        }
        break;
    case PROTO_IPSEC_ESP :
        switch (oAttrId)
        {
        case ESP_DES        : pStr = (sbyte *)"ESP-DES";        break;
        case ESP_3DES       : pStr = (sbyte *)"ESP-3DES";       break;
        case ESP_BLOWFISH   : pStr = (sbyte *)"ESP-BLOWFISH";   break;
/*      case ESP_RC4        : pStr = (sbyte *)"ESP-RC4";        break;*/
        case ESP_NULL       : pStr = (sbyte *)"ESP-NULL";       break;
        case ESP_AES        : pStr = (sbyte *)"ESP-AES";        break;
        case ESP_AES_CTR    : pStr = (sbyte *)"ESP-AES-CTR";    break;
#ifdef __ENABLE_DIGICERT_GCM__
        case ESP_AES_GCM_8      : pStr = (sbyte *)"ESP-AES-GCM-8";  break;
        case ESP_AES_GCM_12     : pStr = (sbyte *)"ESP-AES-GCM-12"; break;
        case ESP_AES_GCM_16     : pStr = (sbyte *)"ESP-AES-GCM-16"; break;
        case ESP_NULL_AES_GMAC  : pStr = (sbyte *)"ESP-AES-GMAC";   break;
#endif
        }
        break;
#ifdef __ENABLE_DIGICERT_IPCOMP__
    case PROTO_IPCOMP :
        switch (oAttrId)
        {
        case IPCOMP_OUI     : pStr = (sbyte *)"IPCOMP-OUI";     break;
        case IPCOMP_DEFLATE : pStr = (sbyte *)"IPCOMP-DEFLATE"; break;
        case IPCOMP_LZS     : pStr = (sbyte *)"IPCOMP-LZS";     break;
        case IPCOMP_LZJH    : pStr = (sbyte *)"IPCOMP-LZJH";    break;
        }
#endif
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)oAttrId);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
    }
} /* debug_print_ike_tfmid */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_notify(ubyte2 wMsgType)
{
    sbyte *pStr;

    switch (wMsgType)
    {
    case INVALID_PAYLOAD_TYPE :         pStr = (sbyte *)"INVALID-PAYLOAD-TYPE"; break;
    case DOI_NOT_SUPPORTED :            pStr = (sbyte *)"DOI-NOT-SUPPORTED"; break;
    case SITUATION_NOT_SUPPORTED :      pStr = (sbyte *)"SITUATION-NOT-SUPPORTED"; break;
    case INVALID_COOKIE :               pStr = (sbyte *)"INVALID-COOKIE"; break;
    case INVALID_MAJOR_VERSION :        pStr = (sbyte *)"INVALID-MAJOR-VERSION"; break;
    case INVALID_MINOR_VERSION :        pStr = (sbyte *)"INVALID-MINOR-VERSION"; break;
    case INVALID_EXCHANGE_TYPE :        pStr = (sbyte *)"INVALID-EXCHANGE-TYPE"; break;
    case INVALID_FLAGS :                pStr = (sbyte *)"INVALID-FLAGS"; break;
    case INVALID_MESSAGE_ID :           pStr = (sbyte *)"INVALID-MESSAGE-ID"; break;
    case INVALID_PROTOCOL_ID :          pStr = (sbyte *)"INVALID-PROTOCOL-ID"; break;
    case INVALID_SPI :                  pStr = (sbyte *)"INVALID-SPI"; break;
    case INVALID_TRANSFORM_ID :         pStr = (sbyte *)"INVALID-TRANSFORM-ID"; break;
    case ATTRIBUTES_NOT_SUPPORTED :     pStr = (sbyte *)"ATTRIBUTES-NOT-SUPPORTED"; break;
    case NO_PROPOSAL_CHOSEN :           pStr = (sbyte *)"NO-PROPOSAL-CHOSEN"; break;
    case BAD_PROPOSAL_SYNTAX :          pStr = (sbyte *)"BAD-PROPOSAL-SYNTAX"; break;
    case PAYLOAD_MALFORMED :            pStr = (sbyte *)"PAYLOAD-MALFORMED"; break;
    case INVALID_KEY_INFORMATION :      pStr = (sbyte *)"INVALID-KEY-INFORMATION"; break;
    case INVALID_ID_INFORMATION :       pStr = (sbyte *)"INVALID-ID-INFORMATION"; break;
    case INVALID_CERT_ENCODING :        pStr = (sbyte *)"INVALID-CERT-ENCODING"; break;
    case INVALID_CERTIFICATE :          pStr = (sbyte *)"INVALID-CERTIFICATE"; break;
    case CERT_TYPE_UNSUPPORTED :        pStr = (sbyte *)"CERT-TYPE-UNSUPPORTED"; break;
    case INVALID_CERT_AUTHORITY :       pStr = (sbyte *)"INVALID-CERT-AUTHORITY"; break;
    case INVALID_HASH_INFORMATION :     pStr = (sbyte *)"INVALID-HASH-INFORMATION"; break;
    case AUTHENTICATION_FAILED :        pStr = (sbyte *)"AUTHENTICATION-FAILED"; break;
    case INVALID_SIGNATURE :            pStr = (sbyte *)"INVALID-SIGNATURE"; break;
    case ADDRESS_NOTIFICATION :         pStr = (sbyte *)"ADDRESS-NOTIFICATION"; break;
    case NOTIFY_SA_LIFETIME :           pStr = (sbyte *)"NOTIFY-SA-LIFETIME"; break;
    case CERTIFICATE_UNAVAILABLE :      pStr = (sbyte *)"CERTIFICATE-UNAVAILABLE"; break;
    case UNSUPPORTED_EXCHANGE_TYPE :    pStr = (sbyte *)"UNSUPPORTED-EXCHANGE-TYPE"; break;
    case UNEQUAL_PAYLOAD_LENGTHS :      pStr = (sbyte *)"UNEQUAL-PAYLOAD-LENGTHS"; break;

    case CONNECTED :                    pStr = (sbyte *)"CONNECTED"; break;

    case IPSEC_RESPONDER_LIFETIME :     pStr = (sbyte *)"RESPONDER-LIFETIME"; break;
    case IPSEC_REPLAY_STATUS :          pStr = (sbyte *)"REPLAY-STATUS"; break;
    case IPSEC_INITIAL_CONTACT :        pStr = (sbyte *)"INITIAL-CONTACT"; break;

    case R_U_THERE :                    pStr = (sbyte *)"R-U-THERE"; break;
    case R_U_THERE_ACK :                pStr = (sbyte *)"R-U-THERE-ACK"; break;

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    case PRESHARED_KEY_HASH :           pStr = (sbyte *)"PRESHARED-KEY-HASH"; break;
#endif
    default :                           pStr = NULL; break;
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wMsgType);
    }
} /* debug_print_ike_notify */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_p1_attr_t(ubyte2 wType)
{
    sbyte *pStr;

    switch (wType)
    {
    case OAKLEY_ENCRYPTION_ALGORITHM    : pStr = (sbyte *)"ENCR"; break;
    case OAKLEY_HASH_ALGORITHM          : pStr = (sbyte *)"HASH"; break;
    case OAKLEY_AUTHENTICATION_METHOD   : pStr = (sbyte *)"AUTH"; break;
    case OAKLEY_GROUP_DESCRIPTION       : pStr = (sbyte *)"GROUP"; break;
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_GROUP_TYPE              : pStr = (sbyte *)"GROUP-TYPE"; break;
#endif
/*  case OAKLEY_GROUP_PRIME             : pStr = (sbyte *)""; break;
    case OAKLEY_GROUP_GENERATOR_ONE     : pStr = (sbyte *)""; break;
    case OAKLEY_GROUP_GENERATOR_TWO     : pStr = (sbyte *)""; break;
    case OAKLEY_GROUP_CURVE_A           : pStr = (sbyte *)""; break;
    case OAKLEY_GROUP_CURVE_B           : pStr = (sbyte *)""; break;*/
    case OAKLEY_LIFE_TYPE               : pStr = (sbyte *)"LIFE-TYPE"; break;
    case OAKLEY_LIFE_DURATION           : pStr = (sbyte *)"LIFE-DURATION"; break;
/*  case OAKLEY_PRF                     : pStr = (sbyte *)""; break;*/
    case OAKLEY_KEY_LENGTH              : pStr = (sbyte *)"KEY-LENGTH"; break;
/*  case OAKLEY_FIELD_SIZE              : pStr = (sbyte *)""; break;
    case OAKLEY_GROUP_ORDER             : pStr = (sbyte *)""; break;
    case OAKLEY_BLOCK_SIZE              : pStr = (sbyte *)""; break;*/
    default                             : pStr = NULL; break;
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wType);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
    }
} /* debug_print_ike_p1_attr_t */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_p1_attr_v(ubyte2 wValue, ubyte2 wType)
{
    sbyte *pStr = NULL;
#ifdef __ENABLE_IKE_XAUTH__
    sbyte *pStr1 = NULL;
#endif

    switch (wType)
    {
    case OAKLEY_ENCRYPTION_ALGORITHM :
        switch (wValue)
        {
        case OAKLEY_DES_CBC         : pStr = (sbyte *)"DES";        break;
/*      case OAKLEY_IDEA_CBC        : pStr = (sbyte *)"IDEA";       break;*/
        case OAKLEY_BLOWFISH_CBC    : pStr = (sbyte *)"BLOWFISH";   break;
/*      case OAKLEY_RC5_R16_B64_CBC : pStr = (sbyte *)"RC5";        break;*/
        case OAKLEY_3DES_CBC        : pStr = (sbyte *)"3DES";       break;
/*      case OAKLEY_CAST_CBC        : pStr = (sbyte *)"CAST";       break;*/
        case OAKLEY_AES_CBC         : pStr = (sbyte *)"AES";        break;
/*      case OAKLEY_CAMELLIA_CBC    : pStr = (sbyte *)"CAMELLIA";   break;*/
        }
        break;
    case OAKLEY_HASH_ALGORITHM :
    {
        IKE_hashSuiteInfo *pHashSuite = IKE_hashSuite(wValue, 0);
        if (NULL != pHashSuite) pStr = pHashSuite->name1;
        break;
    }
    case OAKLEY_AUTHENTICATION_METHOD :
    {
#ifdef __ENABLE_IKE_XAUTH__
        ubyte2 wAuthMtd = wValue;
        if (65000 < wAuthMtd)
        {
            wAuthMtd = (ubyte2)((wAuthMtd - 64999) / 2);
            if ((wValue - 65000) % 2) /* XAUTHInit */
                pStr1 = (sbyte *)"-XAUTH-INIT";
            else /* XAUTHResp */
                pStr1 = (sbyte *)"-XAUTH-RESP";
        }
#ifdef __ENABLE_IKE_HYBRID_RSA__
        else if (HYBRID_INIT_RSA == wAuthMtd)
        {
            wAuthMtd = OAKLEY_RSA_SIG;
            pStr1 = (sbyte *)"-HYBRID-INIT";
        }
        else if (HYBRID_RESP_RSA == wAuthMtd)
        {
            wAuthMtd = OAKLEY_RSA_SIG;
            pStr1 = (sbyte *)"-HYBRID-RESP";
        }
#endif
        switch (wAuthMtd)
#else
        switch (wValue)
#endif
        {
        case OAKLEY_PRESHARED_KEY   : pStr = (sbyte *)"PRESHARED-KEY";  break;
/*      case OAKLEY_DSS_SIG         : pStr = (sbyte *)"DSS-SIG";        break;*/
        case OAKLEY_RSA_SIG         : pStr = (sbyte *)"RSA-SIG";        break;
/*      case OAKLEY_RSA_ENC         : pStr = (sbyte *)"RSA-ENC";        break;
        case OAKLEY_RSA_ENC_REV     : pStr = (sbyte *)"RSA-ENC-REV";    break;*/
#ifdef __ENABLE_DIGICERT_ECC__
        case OAKLEY_ECDSA_SIG       : pStr = (sbyte *)"ECDSA-SIG";      break;
        case OAKLEY_ECDSA_256       : pStr = (sbyte *)"ECDSA-256";      break;
        case OAKLEY_ECDSA_384       : pStr = (sbyte *)"ECDSA-384";      break;
        case OAKLEY_ECDSA_521       : pStr = (sbyte *)"ECDSA-521";      break;
#endif
        case AUTH_MTD_SIG           : pStr = (sbyte *)"RFC7427-SIG";      break;
        case OAKLEY_P256_MLDSA_44   : pStr = (sbyte *)"P256_MLDSA_44";    break;
        case OAKLEY_P256_FNDSA512   : pStr = (sbyte *)"P256_FNDSA512";    break;
        case OAKLEY_P384_MLDSA_65   : pStr = (sbyte *)"P384_MLDSA_65";    break;
        case OAKLEY_P521_FNDSA1024  : pStr = (sbyte *)"P521_FNDSA1024";   break;
        case OAKLEY_P521_MLDSA_87   : pStr = (sbyte *)"P521_MLDSA_87";    break;
        }
        break;
    }
    case OAKLEY_GROUP_DESCRIPTION :
        switch (wValue)
        {
        case OAKLEY_GROUP_MODP768   : pStr = (sbyte *)"MODP768";    break;
        case OAKLEY_GROUP_MODP1024  : pStr = (sbyte *)"MODP1024";   break;
        case OAKLEY_GROUP_MODP1536  : pStr = (sbyte *)"MODP1536";   break;
        case OAKLEY_GROUP_MODP2048  : pStr = (sbyte *)"MODP2048";   break;
        case OAKLEY_GROUP_MODP3072  : pStr = (sbyte *)"MODP3072";   break;
        case OAKLEY_GROUP_MODP4096  : pStr = (sbyte *)"MODP4096";   break;
        case OAKLEY_GROUP_MODP6144  : pStr = (sbyte *)"MODP6144";   break;
        case OAKLEY_GROUP_MODP8192  : pStr = (sbyte *)"MODP8192";   break;
        case OAKLEY_GROUP_MODP2048_256 : pStr = (sbyte *)"MODP2048_256"; break;
#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_PQC__
        case OAKLEY_GROUP_P256_MLKEM512          : pStr = (sbyte *)"ECP256-MLKEM512";          break;

        case OAKLEY_GROUP_P384_MLKEM768          : pStr = (sbyte *)"ECP384-MLKEM768";          break;

        case OAKLEY_GROUP_P521_MLKEM1024         : pStr = (sbyte *)"ECP521-MLKEM1024";         break;
#endif
        case OAKLEY_GROUP_ECP192    : pStr = (sbyte *)"ECP192";     break;
        case OAKLEY_GROUP_ECP224    : pStr = (sbyte *)"ECP224";     break;
        case OAKLEY_GROUP_ECP256    : pStr = (sbyte *)"ECP256";     break;
        case OAKLEY_GROUP_ECP384    : pStr = (sbyte *)"ECP384";     break;
        case OAKLEY_GROUP_ECP521    : pStr = (sbyte *)"ECP521";     break;
#endif
        }
        break;
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_GROUP_TYPE :
        switch (wValue)
        {
        case OAKLEY_GROUP_TYPE_MODP : pStr = (sbyte *)"MODP";   break;
        case OAKLEY_GROUP_TYPE_ECP  : pStr = (sbyte *)"ECP";    break;
        case OAKLEY_GROUP_TYPE_EC2N : pStr = (sbyte *)"EC2N";   break;
        }
        break;
#endif
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
#ifdef __ENABLE_IKE_XAUTH__
        if (NULL != pStr1)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr1);
        }
#endif
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'\'');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wValue);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'\'');
    }
} /* debug_print_ike_p1_attr_v */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_p2_attr_v(ubyte2 wValue, ubyte2 wType)
{
    sbyte *pStr = NULL;

    switch (wType)
    {
    case AUTH_ALGORITHM :
        switch (wValue)
        {
        case AUTH_ALGORITHM_HMAC_MD5        : pStr = (sbyte *)"HMAC-MD5"; break;
        case AUTH_ALGORITHM_HMAC_SHA        : pStr = (sbyte *)"HMAC-SHA1"; break;
        case AUTH_ALGORITHM_HMAC_SHA2_256   : pStr = (sbyte *)"HMAC-SHA2-256"; break;
        case AUTH_ALGORITHM_HMAC_SHA2_384   : pStr = (sbyte *)"HMAC-SHA2-384"; break;
        case AUTH_ALGORITHM_HMAC_SHA2_512   : pStr = (sbyte *)"HMAC-SHA2-512"; break;
        case AUTH_ALGORITHM_AES_XCBC_MAC    : pStr = (sbyte *)"AES-XCBC-MAC"; break;
        }
        break;
    case ENCAPSULATION_MODE :
        switch (wValue)
        {
        case ENCAPSULATION_MODE_TUNNEL              : pStr = (sbyte *)"TUNNEL"; break;
        case ENCAPSULATION_MODE_TRANSPORT           : pStr = (sbyte *)"TRANSPORT"; break;
        case ENCAPSULATION_MODE_UDP_TUNNEL          : pStr = (sbyte *)"UDP-TUNNEL"; break;
        case ENCAPSULATION_MODE_UDP_TRANSPORT       : pStr = (sbyte *)"UDP-TRANSPORT"; break;
        case ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS   : pStr = (sbyte *)"UDP-TUNNEL-DRAFTS"; break;
        case ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS: pStr = (sbyte *)"UDP-TRANSPORT-DRAFTS"; break;
        }
        break;
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'\'');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wValue);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'\'');
    }
} /* debug_print_ike_p2_attr_v */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_dn(ubyte *poDn, ubyte2 wDnLen)
{
    MSTATUS status;

    certDistinguishedName *pxCertDN = NULL;
    relativeDN *dn;
    ubyte4 i, j, k;

    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'{');

    if (OK > (status = IKE_certGetDN(poDn, wDnLen, &pxCertDN)))
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"error#");
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)status);
        goto exit;
    }

    dn = pxCertDN->pDistinguishedName;

    for (i = pxCertDN->dnCount; i > 0; i--, dn++)
    {
        nameAttr *na = dn->pNameAttr;

        for (j = dn->nameAttrCount; j > 0; j--, na++)
        {
            const ubyte *oid = na->oid;
            sbyte *pStr = (sbyte *)"?";
            intBoolean bPrintString = TRUE;

            if      (EqualOID(oid, countryName_OID))            pStr = (sbyte *)"C";
            else if (EqualOID(oid, stateOrProvinceName_OID))    pStr = (sbyte *)"S";
            else if (EqualOID(oid, localityName_OID))           pStr = (sbyte *)"L";
            else if (EqualOID(oid, organizationName_OID))       pStr = (sbyte *)"O";
            else if (EqualOID(oid, organizationalUnitName_OID)) pStr = (sbyte *)"OU";
            else if (EqualOID(oid, commonName_OID))             pStr = (sbyte *)"CN";
            else if (EqualOID(oid, pkcs9_emailAddress_OID))     pStr = (sbyte *)"E";
            else if (EqualOID(oid, domainComponent_OID))        pStr = (sbyte *)"D";

            DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'=');

            switch (na->type)
            {
            case NUMERICSTRING   : /* 18: Numeric string */
            case PRINTABLESTRING : /* 19: Printable string (ASCII subset) */
            case IA5STRING       : /* 22: IA5/ASCII string */
            case VISIBLESTRING   : /* 26: Visible string (ASCII subset) */
                break;
            default :
                DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'(');
                DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) na->type);
                DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)')');
                bPrintString = FALSE;
                break;
            }

            for (k = 0; k < na->valueLen; k++)
            {
                if (bPrintString)
                {
                    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte) na->value[k]);
                }
                else
                {
                    DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, (sbyte) na->value[k]);
                }
            }

            if (1 != j)
            {
                DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)',');
            }
        } /* for (j */

        if (1 != i)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
        }
    } /* for (i */

exit:
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'}');

    if (NULL != pxCertDN)
        CA_MGMT_freeCertDistinguishedName(&pxCertDN);

    return;
} /* debug_print_ike_dn */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_id2(ubyte *poHdr, intBoolean bInitiator)
{
    struct ikeIdHdr *pxIdHdr = (struct ikeIdHdr *)poHdr;
    ubyte *poId = poHdr + SIZEOF_IKE_ID_HDR;
    ubyte2 wIdLen = GET_NTOHS(pxIdHdr->wLength) - (ubyte2)SIZEOF_IKE_ID_HDR;
    sbyte4 i;

    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"   IDc");
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)(bInitiator ? 'i' : 'r'));
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)": ");

    switch (pxIdHdr->oType)
    {
    case ID_IPV4_ADDR :
        debug_print_ip4(GET_NTOHL(pxIdHdr->dwIpAddr));
        break;
    case ID_IPV4_ADDR_RANGE :
        debug_print_ip4(GET_NTOHL(pxIdHdr->dwIpAddr));
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'~');
        debug_print_ip4(GET_NTOHL(pxIdHdr->dwIpAddrEnd));
        break;
    case ID_IPV4_ADDR_SUBNET :
        debug_print_ip4(GET_NTOHL(pxIdHdr->dwIpAddr));
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'/');
        debug_print_ip4(GET_NTOHL(pxIdHdr->dwIpAddrEnd));
        break;
    case ID_FQDN :
    case ID_USER_FQDN :
        for (i=0; i < wIdLen; i++)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte) poId[i]);
        }
        break;
    case ID_IPV6_ADDR :
        debug_print_ip6(poId);
        break;
    case ID_IPV6_ADDR_RANGE :
        debug_print_ip6(poId);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'~');
        debug_print_ip6(poId + 16);
        break;
    case ID_IPV6_ADDR_SUBNET :
        debug_print_ip6(poId);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'/');
        debug_print_ip6(poId + 16);
        break;
    case ID_KEY_ID :
        for (i=0; i < wIdLen; i++)
        {
            DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, (sbyte) poId[i]);
        }
        break;
    case ID_DER_ASN1_DN :
        debug_print_ike_dn(poId, wIdLen);
        break;
    case ID_DER_ASN1_GN :
    default :
        /* FOR NOW */
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"{...}");
        break;
    }

    if (0 != pxIdHdr->wPort)
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'[');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) GET_NTOHS(pxIdHdr->wPort));
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)']');
    }

    if (0 != pxIdHdr->oProtocol)
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
        debug_print_ip_proto(pxIdHdr->oProtocol);
    }

    DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
} /* debug_print_ike_id2 */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_cfgtype(ubyte type)
{
    sbyte *pStr = NULL;

    switch (type)
    {
    case CFG_REQUEST    : pStr = (sbyte *)"REQUEST";    break;
    case CFG_REPLY      : pStr = (sbyte *)"REPLY";      break;
    case CFG_SET        : pStr = (sbyte *)"SET";        break;
    case CFG_ACK        : pStr = (sbyte *)"ACK";        break;

    /* draft-ietf-ipsec-isakmp-xauth-01...02 */
    case CFG_AUTH_OK        :
    case CFG_AUTH_OK_1      : pStr = (sbyte *)"AUTH_OK"; break;
    case CFG_AUTH_FAILED    :
    case CFG_AUTH_FAILED_1  : pStr = (sbyte *)"AUTH_FAILED"; break;
    }

    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"CFG_");

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)type);
    }
} /* debug_print_ike_cfgtype */


/*------------------------------------------------------------------*/

static void
debug_print_ike_cfgattr_t(ubyte2 type)
{
    sbyte *pStr = NULL;

    switch ((sbyte4)type)
    {
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    case INTERNAL_IP4_ADDRESS       : pStr = (sbyte *)"IP4_ADDRESS";    break;
    case INTERNAL_IP4_NETMASK       : pStr = (sbyte *)"IP4_NETMASK";    break;
    case INTERNAL_IP4_DNS           : pStr = (sbyte *)"IP4_DNS";        break;
    case INTERNAL_IP4_NBNS          : pStr = (sbyte *)"IP4_NBNS";       break;
    case INTERNAL_ADDRESS_EXPIRY    : pStr = (sbyte *)"ADDR_EXP";       break;
    case INTERNAL_IP4_DHCP          : pStr = (sbyte *)"IP4_DHCP";       break;
    case APPLICATION_VERSION        : pStr = (sbyte *)"APP_VER";        break;
    case INTERNAL_IP6_ADDRESS       : pStr = (sbyte *)"IP6_ADDRESS";    break;
#ifdef __ENABLE_IKE_MODE_CFG__
    case INTERNAL_IP6_NETMASK       : pStr = (sbyte *)"IP6_NETMASK";    break;
#endif
    case INTERNAL_IP6_DNS           : pStr = (sbyte *)"IP6_DNS";        break;
    /*case INTERNAL_IP6_NBNS        : pStr = (sbyte *)"IP6_NBNS";       break;*//* removed [RFC5996] */
    case INTERNAL_IP6_DHCP          : pStr = (sbyte *)"IP6_DHCP";       break;
    case INTERNAL_IP4_SUBNET        : pStr = (sbyte *)"IP4_SUBNET";     break;
    case SUPPORTED_ATTRIBUTES       : pStr = (sbyte *)"SUPPORTED";      break;
    case INTERNAL_IP6_SUBNET        : pStr = (sbyte *)"IP6_SUBNET";     break;

    case INTERNAL_DFLT_DOMAIN_CISCO : pStr = (sbyte *)"CISCO_DEF_DOMAIN"; break;
    case INTERNAL_IP4_SUBNET_CISCO  : pStr = (sbyte *)"CISCO_IP4_SUBNET"; break;
    case CISCO_DO_PFS               : pStr = (sbyte *)"CISCO_DO_PFS";   break;
#endif

#ifdef __ENABLE_IKE_XAUTH__
    case XAUTH_TYPE_1       :       /* draft-ietf-ipsec-isakmp-xauth-01 */
#if !(defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__))
    case XAUTH_TYPE_25      :       /* draft-ietf-ipsec-isakmp-xauth-02...05 */
#endif
    case XAUTH_TYPE                 : pStr = (sbyte *)"TYPE";           break;
    case XAUTH_USER_NAME_1  :
#if !(defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__))
    case XAUTH_USER_NAME_25 :
#endif
    case XAUTH_USER_NAME            : pStr = (sbyte *)"USER-NAME";      break;
    case XAUTH_USER_PASSWORD_1  :
#if !(defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__))
    case XAUTH_USER_PASSWORD_25 :
#endif
    case XAUTH_USER_PASSWORD        : pStr = (sbyte *)"USER-PASSWORD";  break;
    case XAUTH_PASSCODE_1   :
    case XAUTH_PASSCODE_25  :
    case XAUTH_PASSCODE             : pStr = (sbyte *)"PASSCODE";       break;
    case XAUTH_MESSAGE_1    :
    case XAUTH_MESSAGE_25   :
    case XAUTH_MESSAGE              : pStr = (sbyte *)"MESSAGE";        break;
    case XAUTH_CHALLENGE_1  :
    case XAUTH_CHALLENGE_25 :
    case XAUTH_CHALLENGE            : pStr = (sbyte *)"CHALLENGE";      break;
    case XAUTH_DOMAIN_1     :
    case XAUTH_DOMAIN_25    :
    case XAUTH_DOMAIN               : pStr = (sbyte *)"DOMAIN";         break;
    case XAUTH_STATUS_35    :       /* draft-ietf-ipsec-isakmp-xauth-03...05 */
    case XAUTH_STATUS               : pStr = (sbyte *)"STATUS";         break;
    case XAUTH_NEXT_PIN             : pStr = (sbyte *)"NEXT-PIN";       break;
    case XAUTH_ANSWER               : pStr = (sbyte *)"ANSWER";         break;
                                    /* draft-ietf-ipsec-isakmp-xauth-03...04 */
    case XAUTH_REQ_NUMBER           : pStr = (sbyte *)"REQ-NUMBER";     break;

#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    case MOCANA_TUNNEL_MTU          : pStr = (sbyte *)"TUNNEL_MTU";     break;
    case XAUTH_MOCANA_PERP          : pStr = (sbyte *)"XAUTH_PERP";     break;
#endif
#endif /* __ENABLE_IKE_XAUTH__ */

    default : break;
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'\'');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)type);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'\'');
    }
} /* debug_print_ike_cfgattr_t */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_cfgattr(ubyte2 type, ubyte2 len, const ubyte *data)
{
#ifdef __ENABLE_IKE_XAUTH__
    ubyte2 wVal;
    sbyte *pStr = NULL;
#endif
#if defined(__ENABLE_IKE_XAUTH__) || defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    sbyte4 i;
#else
    MOC_UNUSED(data);
#endif
    debug_print_ike_cfgattr_t(type);

    if (0 == len) return;

    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'(');

    switch ((sbyte4)type)
    {
#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    case INTERNAL_IP4_ADDRESS :
    case INTERNAL_IP4_NETMASK :
    case INTERNAL_IP4_DNS :
    case INTERNAL_IP4_NBNS :
    case INTERNAL_IP4_DHCP :        /* 4 */
        if (4 > len) goto bad_len;
        debug_print_ip4(DIGI_NTOHL(data));
        break;
    case INTERNAL_ADDRESS_EXPIRY :  /* 4 */
        if (4 > len) goto bad_len;
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) DIGI_NTOHL(data));
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" secs");
        break;
    case INTERNAL_IP4_SUBNET :      /* 8 */
        if (8 > len) goto bad_len;
        debug_print_ip4(DIGI_NTOHL(data));
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'/');
        debug_print_ip4(DIGI_NTOHL(data+4));
        break;
    case INTERNAL_DFLT_DOMAIN_CISCO :
    case APPLICATION_VERSION :
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        for (i=0; i < len; i ++)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)data[i]);
        }
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        break;
    case INTERNAL_IP6_ADDRESS :     /* [v1] 16 or [v2] 17 */
#ifdef __ENABLE_IKE_MODE_CFG__  /* [v1] */
        if (16 > len) goto bad_len;
#ifdef __ENABLE_IKE_CP__        /* [v2] */
        if (16 == len)
#endif
        {
            debug_print_ip6(data);
            break;
        }
        /* fall through */
#endif
    case INTERNAL_IP6_SUBNET :      /* 17 */
        if (17 > len) goto bad_len;
        debug_print_ip6(data);
        if (data[16])
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'/');
            DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) data[16]);
        }
        break;
#ifdef __ENABLE_IKE_MODE_CFG__
    case INTERNAL_IP6_NETMASK :     /* [v1] 16 */
#endif
    case INTERNAL_IP6_DNS :
    /*case INTERNAL_IP6_NBNS :*//* removed [RFC5996] */
    case INTERNAL_IP6_DHCP :        /* 16 */
        if (16 > len) goto bad_len;
        debug_print_ip6(data);
        break;
    case SUPPORTED_ATTRIBUTES :     /* 2x */
        for (i=0; i < len/2; i++)
        {
            if (i)
            {
                DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)',');
            }
            debug_print_ike_cfgattr_t(DIGI_NTOHS(data + (i * 2)));
        }
        break;
    case INTERNAL_IP4_SUBNET_CISCO :
        for (i=0; i < len/14; i++)
        {
            if (i)
            {
                DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
            }
            debug_print_ip4(DIGI_NTOHL(data + (i * 14)));
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'/');
            debug_print_ip4(DIGI_NTOHL(data + (i * 14) + 4));
        }
        break;
#endif /* defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__) */

#ifdef __ENABLE_IKE_XAUTH__
    case XAUTH_TYPE             : /* B */
    case XAUTH_TYPE_1           :       /* draft-ietf-ipsec-isakmp-xauth-01 */
#if !(defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__))
    case XAUTH_TYPE_25          :       /* draft-ietf-ipsec-isakmp-xauth-02...05 */
#endif
        if (2 > len) goto bad_len;
        pStr = NULL;
        wVal = DIGI_NTOHS(data);
        switch(wVal)
        {
        case XAUTH_TYPE_GENERIC     : pStr = (sbyte *)"Generic";        break;
        case XAUTH_TYPE_RADIUS_CHAP : pStr = (sbyte *)"RADIUS-CHAP";    break;
        case XAUTH_TYPE_OTP         : pStr = (sbyte *)"OTP";            break;
        case XAUTH_TYPE_SKEY        : pStr = (sbyte *)"S/KEY";          break;
        }
        if (NULL != pStr)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
        }
        else
        {
            DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wVal);
        }
        break;
    case XAUTH_STATUS           : /* B */
    case XAUTH_STATUS_35        :       /* draft-ietf-ipsec-isakmp-xauth-03...05 */
        if (2 > len) goto bad_len;
        pStr = NULL;
        wVal = DIGI_NTOHS(data);
        switch(wVal)
        {
        case XAUTH_STATUS_FAIL      : pStr = (sbyte *)"FAIL";   break;
        case XAUTH_STATUS_OK        : pStr = (sbyte *)"OK";     break;
        }
        if (NULL != pStr)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
        }
        else
        {
            DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wVal);
        }
        break;
    case XAUTH_REQ_NUMBER       : /* B *//* draft-ietf-ipsec-isakmp-xauth-03...04 */
        if (2 > len) goto bad_len;
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)DIGI_NTOHS(data));
        break;
    case XAUTH_USER_NAME        :
    case XAUTH_USER_NAME_1      :
#if !(defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__))
    case XAUTH_USER_NAME_25     :
#endif
    case XAUTH_MESSAGE          :
    case XAUTH_MESSAGE_1        :
    case XAUTH_MESSAGE_25       :
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        for (i=0; i < len; i ++)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)data[i]);
        }
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        break;
    case XAUTH_CHALLENGE        :
    case XAUTH_CHALLENGE_1      :
    case XAUTH_CHALLENGE_25     :
    case XAUTH_DOMAIN           :
    case XAUTH_DOMAIN_1         :
    case XAUTH_DOMAIN_25        :
        for (i=0; i < len; i ++)
        {
            if (i)
            {
                DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
            }
            DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, (sbyte)data[i]);
        }
        break;
    case XAUTH_USER_PASSWORD    :
    case XAUTH_USER_PASSWORD_1  :
#if !(defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__))
    case XAUTH_USER_PASSWORD_25 :
#endif
    case XAUTH_PASSCODE         :
    case XAUTH_PASSCODE_1       :
    case XAUTH_PASSCODE_25      :
    case XAUTH_NEXT_PIN         :
    case XAUTH_ANSWER           :
        for (i=0; i < len; i ++)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'*');
        }
        break;
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    case MOCANA_TUNNEL_MTU      :
        if (4 > len) goto bad_len;
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)DIGI_NTOHL(data));
        break;
#endif
#endif /* __ENABLE_IKE_XAUTH__*/

    default :
        if (2 == len)
        {
            DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)DIGI_NTOHS(data));
        }
        else
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'[');
            DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)len);
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)']');
        }
        break;
    }

#if defined(__ENABLE_IKE_XAUTH__) || defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__)
    goto done;

bad_len:
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'[');
    DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)len);
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"!]");

done:
#endif
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)')');
} /* debug_print_ike_cfgattr */


/*------------------------------------------------------------------*/

typedef struct cfgattr_cb
{
    sbyte *pIndent;
    intBoolean bXauth;

} *CFGATTR_CB;


static MSTATUS
PrintCfgAttrs(void *cb, ubyte2 wType, intBoolean bBasic,
              ubyte2 wLen, const ubyte *poAttr)
{
    if (NULL != ((CFGATTR_CB)cb)->pIndent)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, ((CFGATTR_CB)cb)->pIndent);
    }

#if defined(__ENABLE_IKE_XAUTH__) && (defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_CP__))
    /* draft-ietf-ipsec-isakmp-xauth-02...05 */
    if (((CFGATTR_CB)cb)->bXauth)
    {
        /* these values conflict with Mode-Cfg or CP */
        switch (wType)
        {
        case XAUTH_TYPE_25          : wType = XAUTH_TYPE;           break;
        case XAUTH_USER_NAME_25     : wType = XAUTH_USER_NAME;      break;
        case XAUTH_USER_PASSWORD_25 : wType = XAUTH_USER_PASSWORD;  break;
        }
    }
#endif
    debug_print_ike_cfgattr(wType, (bBasic ? 2 : wLen), poAttr);
    DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");

    return OK;
} /* PrintCfgAttrs */


/*------------------------------------------------------------------*/

extern void
debug_print_ike_cfg_attrs(const ubyte *attrs, ubyte2 len,
                          sbyte *indent, intBoolean xauth)
{
    struct cfgattr_cb cb;
    cb.pIndent = indent;
    cb.bXauth = xauth;

    IKE_travAttrs(attrs, len, &cb, PrintCfgAttrs);
}


/*------------------------------------------------------------------*/

extern void
debug_print_status(sbyte *file, sbyte4 lineno, sbyte4 status)
{
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, file);
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)" (");
    DEBUG_INT(DEBUG_IKE_MESSAGES, lineno);
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"): ");
#ifdef __ENABLE_LOOKUP_TABLE__
    DISPLAY_ERROR(DEBUG_IKE_MESSAGES, (MSTATUS)status)
#else
    DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"errorCode = ", status);
#endif
} /* debug_print_status */


/*------------------------------------------------------------------*/

extern void
debug_print_st(sbyte4 st)
{
    MSTATUS status = (MSTATUS)st;

    if (OK != status)
    {
#ifdef __ENABLE_LOOKUP_TABLE__
        sbyte *pStatus = (STATUS_IPSEC_FINDSA_NULL == status)
                       ? (sbyte *)"NULL"
                       : (sbyte *) MERROR_lookUpErrorCode(status);
#endif
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'=');

#ifdef __ENABLE_LOOKUP_TABLE__
        if (NULL != pStatus)
        {
            DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStatus);
        }
        else
#endif
        {
            DEBUG_INT(DEBUG_IKE_MESSAGES, st);
        }
    }
    DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
} /* debug_print_st */


/* IKEv2 */

/*------------------------------------------------------------------*/

extern void
debug_print_ike2_notify(ubyte2 wMsgType)
{
    sbyte *pStr;

    switch (wMsgType)
    {
    /* [v2] error types (0 - 16383) */
    case UNSUPPORTED_CRITICAL_PAYLOAD : pStr = (sbyte *)"UNSUPPORTED_CRITICAL_PAYLOAD"; break;
    case INVALID_IKE_SPI :              pStr = (sbyte *)"INVALID_IKE_SPI"; break;
    case INVALID_MAJOR_VERSION :        pStr = (sbyte *)"INVALID_MAJOR_VERSION"; break;
    case INVALID_SYNTAX :               pStr = (sbyte *)"INVALID_SYNTAX"; break;
    case INVALID_MESSAGE_ID :           pStr = (sbyte *)"INVALID_MESSAGE_ID"; break;
    case INVALID_SPI :                  pStr = (sbyte *)"INVALID_SPI"; break;
    case NO_PROPOSAL_CHOSEN :           pStr = (sbyte *)"NO_PROPOSAL_CHOSEN"; break;
    case INVALID_KE_PAYLOAD :           pStr = (sbyte *)"INVALID_KE_PAYLOAD"; break;
    case AUTHENTICATION_FAILED :        pStr = (sbyte *)"AUTHENTICATION_FAILED"; break;
    case SINGLE_PAIR_REQUIRED :         pStr = (sbyte *)"SINGLE_PAIR_REQUIRED"; break;
    case NO_ADDITIONAL_SAS :            pStr = (sbyte *)"NO_ADDITIONAL_SAS"; break;
    case INTERNAL_ADDRESS_FAILURE :     pStr = (sbyte *)"INTERNAL_ADDRESS_FAILURE"; break;
    case FAILED_CP_REQUIRED :           pStr = (sbyte *)"FAILED_CP_REQUIRED"; break;
    case TS_UNACCEPTABLE :              pStr = (sbyte *)"TS_UNACCEPTABLE"; break;
    case INVALID_SELECTORS :            pStr = (sbyte *)"INVALID_SELECTORS"; break;
    case UNACCEPTABLE_ADDRESSES :       pStr = (sbyte *)"UNACCEPTABLE_ADDRESSES"; break;
    case UNEXPECTED_NAT_DETECTED :      pStr = (sbyte *)"UNEXPECTED_NAT_DETECTED"; break;

    /* Private Use - Errors         8192 - 16383 */

    /* [v2] status types */
    case INITIAL_CONTACT :              pStr = (sbyte *)"INITIAL_CONTACT"; break;
    case SET_WINDOW_SIZE :              pStr = (sbyte *)"SET_WINDOW_SIZE"; break;
    case ADDITIONAL_TS_POSSIBLE :       pStr = (sbyte *)"ADDITIONAL_TS_POSSIBLE"; break;
    case IPCOMP_SUPPORTED :             pStr = (sbyte *)"IPCOMP_SUPPORTED"; break;
    case NAT_DETECTION_SOURCE_IP :      pStr = (sbyte *)"NAT_DETECTION_SOURCE_IP"; break;
    case NAT_DETECTION_DESTINATION_IP : pStr = (sbyte *)"NAT_DETECTION_DESTINATION_IP"; break;
    case NOTIFY_COOKIE :                pStr = (sbyte *)"COOKIE"; break;
    case USE_TRANSPORT_MODE :           pStr = (sbyte *)"USE_TRANSPORT_MODE"; break;
    case HTTP_CERT_LOOKUP_SUPPORTED :   pStr = (sbyte *)"HTTP_CERT_LOOKUP_SUPPORTED"; break;
    case NOTIFY_REKEY_SA :              pStr = (sbyte *)"REKEY_SA"; break;
    case ESP_TFC_PADDING_NOT_SUPPORTED :pStr = (sbyte *)"ESP_TFC_PADDING_NOT_SUPPORTED"; break;
    case NON_FIRST_FRAGMENTS_ALSO :     pStr = (sbyte *)"NON_FIRST_FRAGMENTS_ALSO"; break;
    case MOBIKE_SUPPORTED :             pStr = (sbyte *)"MOBIKE_SUPPORTED"; break;
    case ADDITIONAL_IP4_ADDRESS :       pStr = (sbyte *)"ADDITIONAL_IP4_ADDRESS"; break;
    case ADDITIONAL_IP6_ADDRESS :       pStr = (sbyte *)"ADDITIONAL_IP6_ADDRESS"; break;
    case NO_ADDITIONAL_ADDRESSES :      pStr = (sbyte *)"NO_ADDITIONAL_ADDRESSES"; break;
    case UPDATE_SA_ADDRESSES :          pStr = (sbyte *)"UPDATE_SA_ADDRESSES"; break;
    case COOKIE2 :                      pStr = (sbyte *)"COOKIE2"; break;
    case NO_NATS_ALLOWED :              pStr = (sbyte *)"NO_NATS_ALLOWED"; break;
    case AUTH_LIFETIME :                pStr = (sbyte *)"AUTH_LIFETIME"; break;
    case MULTIPLE_AUTH_SUPPORTED :      pStr = (sbyte *)"MULTIPLE_AUTH_SUPPORTED"; break;
    case ANOTHER_AUTH_FOLLOWS :         pStr = (sbyte *)"ANOTHER_AUTH_FOLLOWS"; break;
    case REDIRECT_SUPPORTED :           pStr = (sbyte *)"REDIRECT_SUPPORTED"; break;
    case REDIRECT :                     pStr = (sbyte *)"REDIRECT"; break;
    case REDIRECTED_FROM :              pStr = (sbyte *)"REDIRECTED_FROM"; break;
    case EAP_ONLY_AUTHENTICATION :      pStr = (sbyte *)"EAP_ONLY_AUTHENTICATION"; break;
    case IKEV2_FRAGMENTATION_SUPPORTED :pStr = (sbyte *)"IKEV2_FRAGMENTATION_SUPPORTED"; break;
    case USE_PPK              :         pStr = (sbyte *)"USE_PPK"; break;
    case PPK_IDENTITY         :         pStr = (sbyte *)"PPK_IDENTITY"; break;
    case NO_PPK_AUTH          :         pStr = (sbyte *)"NO_PPK_AUTH"; break;
    case SIGNATURE_HASH_ALGORITHMS :    pStr = (sbyte *)"SIGNATURE_HASH_ALGORITHMS"; break;

    default :                           pStr = NULL; break;
    }

    if (NULL != pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wMsgType);
    }
} /* debug_print_ike2_notify */


/*------------------------------------------------------------------*/

extern void
debug_print_ike2_tfm(ubyte2 wId, ubyte oType)
{
    sbyte *pStr0 = NULL;
    sbyte *pStr = NULL;

    switch (oType)
    {
    case TFM_ENCR   :
        pStr0 = (sbyte *)"ENCR";
        switch (wId)
        {
        case ENCR_DES           : pStr = (sbyte *)"DES";            break;
        case ENCR_3DES          : pStr = (sbyte *)"3DES";           break;
        case ENCR_BLOWFISH      : pStr = (sbyte *)"BLOWFISH";       break;
        case ENCR_NULL          : pStr = (sbyte *)"NULL";           break;
        case ENCR_AES_CBC       : pStr = (sbyte *)"AES";            break;
        case ENCR_AES_CTR       : pStr = (sbyte *)"AES_CTR";        break;
#ifdef __ENABLE_DIGICERT_GCM__
        case ENCR_AES_GCM_8     : pStr = (sbyte *)"AES_GCM_8";      break;
        case ENCR_AES_GCM_12    : pStr = (sbyte *)"AES_GCM_12";     break;
        case ENCR_AES_GCM_16    : pStr = (sbyte *)"AES_GCM_16";     break;
        case ENCR_NULL_AES_GMAC : pStr = (sbyte *)"AES_GMAC";       break;
#endif
        }
        break;
    case TFM_PRF :
#ifndef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
        if (wId == PRF_HMAC_SHA1)
        {
            pStr = (sbyte *)"HMAC_SHA1";
        }
        else if (wId == PRF_HMAC_MD5)
        {
            pStr = (sbyte *)"HMAC_MD5";
        }
        else
#endif
        {
            IKE_hashSuiteInfo *pHashSuite = IKE_hashSuite(0, wId);
            if (NULL != pHashSuite) pStr = pHashSuite->name2;
        }
        pStr0 = (sbyte *)"PRF";
        break;
    case TFM_INTEG:
#ifndef __ENABLE_DIGICERT_IKE_UNSECURE_HASH__
        if (wId == AUTH_HMAC_SHA1_96)
        {
            pStr = (sbyte *)"HMAC_SHA1_96";
        }
        else if (wId == AUTH_HMAC_MD5_96)
        {
            pStr = (sbyte *)"HMAC_MD5_96";
        }
        else
#endif
        {
            IKE_macSuiteInfo *pMacSuite = IKE_macSuite(wId);
            if (NULL != pMacSuite) pStr = pMacSuite->name;
        }
        pStr0 = (sbyte *)"AUTH";
        break;
    case TFM_DH   :
        pStr0 = (sbyte *)"DH";
        break;
    case TFM_ESN   :
        pStr0 = (sbyte *)"ESN";
        break;
    }

    if (pStr0)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr0);
    }
    else
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)oType);
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'"');
    }

    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'_');

    if (pStr)
    {
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, pStr);
    }
    else
    {
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4)wId);
    }
} /* debug_print_ike2_tfm */


/*------------------------------------------------------------------*/

extern void
debug_print_ike2_ts(ubyte *poHdr, intBoolean bInitiator)
{
    struct ikeTS *pxTs = (struct ikeTS *)poHdr;

    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"   TS");
    DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)(bInitiator ? 'i' : 'r'));
    DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)": ");

    switch (pxTs->oType)
    {
    case TS_IPV4_ADDR_RANGE :
        debug_print_ip4(GET_NTOHL(pxTs->dwIpAddr));
        if (pxTs->dwIpAddr != pxTs->dwIpAddrEnd)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'~');
            debug_print_ip4(GET_NTOHL(pxTs->dwIpAddrEnd));
        }
        break;
    case TS_IPV6_ADDR_RANGE :
    {
        sbyte4 res;
        ubyte *poIp = poHdr + SIZEOF_IKE_TS;
        debug_print_ip6(poIp);
        if ((OK > DIGI_MEMCMP(poIp, poIp+16, 16, &res)) || res)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'~');
            debug_print_ip6(poIp + 16);
        }
        break;
    }
    default :
        /* FOR NOW */
        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"{...}");
        break;
    }

    if ((0 != pxTs->wPort) || (0xffff != pxTs->wPortEnd))
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'[');
        DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) GET_NTOHS(pxTs->wPort));
        if (pxTs->wPort != pxTs->wPortEnd)
        {
            DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)'-');
            DEBUG_INT(DEBUG_IKE_MESSAGES, (sbyte4) GET_NTOHS(pxTs->wPortEnd));
        }
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)']');
    }

    if (pxTs->oProtocol)
    {
        DEBUG_PRINTBYTE(DEBUG_IKE_MESSAGES, (sbyte)' ');
        debug_print_ip_proto(pxTs->oProtocol);
    }

    DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
} /* debug_print_ike2_ts */

#endif /* defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__) */


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

