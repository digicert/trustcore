/**
 * @file  ipsecconf.c
 * @brief NanoSec IPsec SPD table configuration implementation.
 *
 * @details    This file contains SPD (Security Policy Database) table configuration.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
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

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_RB_SADB__
#include "../common/hash_table.h"
#include "../common/hash_value.h"
#endif
#include "../crypto/crypto.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_crypto.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/spd.h"
#include "../ipsec/ipsec_utils.h"

#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)
extern hashTableOfPtrs *m_hashTableFqdnMapping;
/* RTOS_MUTEX m_mtxFqdnMapping = NULL; */
ubyte m_unicastRangeCount = 0;
MOC_IP_ADDRESS_S m_startUnicastIP[MAX_UNICAST_RANGE];
MOC_IP_ADDRESS_S m_endUnicastIP[MAX_UNICAST_RANGE];
#endif


/*------------------------------------------------------------------------*/
#ifdef __ENABLE_RB_SADB__
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
static MSTATUS
addUnicastRange(IPSECCONF pxConf)
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
            COPY_MOC_IPADDR(m_startUnicastIP[m_unicastRangeCount], pxConf->dwDestIP);
            COPY_MOC_IPADDR(m_endUnicastIP[m_unicastRangeCount], pxConf->dwDestIPEnd);
            m_unicastRangeCount++;
        }
    }

exit:
    return status;
} /* addUnicastRange */
#endif
#endif


#if defined(__ENABLE_RB_SADB__) && defined(__ENABLE_DIGICERT_MCP_FQDN_SUPPORT__)

/*------------------------------------------------------------------------*/
extern MSTATUS
matchFqdnIp(fqdnMappingConfig *fqdnMapping, fqdnMappingConfig *testFqdnMapping, intBoolean *isMatch)
{
    MSTATUS status = OK;
    *isMatch = FALSE;

    if ((!fqdnMapping) || (!testFqdnMapping))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (SAME_MOC_IPADDR(fqdnMapping->fqdnIp, testFqdnMapping->fqdnIp))
    {
        *isMatch = TRUE;
    }
exit:
    return status;
}


/*------------------------------------------------------------------------*/

static MSTATUS
addFqdnMappingInHash(IPSECCONF pxConf)
{
    MSTATUS status = OK;
    ubyte4 ipListhashValue = 0;
    intBoolean isEntryFound = FALSE;
    fqdnMappingConfig *fqdnMapping = NULL, *fqdnFoundMapping = NULL;
    if (NULL == pxConf)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (pxConf->isUnicastGDOI)
    {
        if (!(pxConf->flags ^ IPSEC_SP_FLAG_INIT))
        {
            /* Use the Base address of FQDN list as the key for FQDN Mapping table */
            pxConf->fqdnUniqueKey = pxConf->dwDestIPList[0];

            ubyte4 listIndex = 0;
            while (listIndex < pxConf->dwDestIPCount)
            {
                /* Generate a new FQDN to be added in the fqdn mapping hash*/
                DIGI_MALLOC((void **)&fqdnMapping, sizeof(fqdnMappingConfig));
                COPY_MOC_IPADDR(fqdnMapping->fqdnUniqueKey, pxConf->fqdnUniqueKey);

                GEN_FQDNMAPPING_HASH_VALUE(pxConf->dwDestIPList[listIndex], ipListhashValue)
                COPY_MOC_IPADDR(fqdnMapping->fqdnIp, pxConf->dwDestIPList[listIndex]);
                /* Check if entry already exists in FqdnMapping hash table */
                status = HASH_TABLE_findPtr(m_hashTableFqdnMapping, ipListhashValue, fqdnMapping,
                            (funcPtrExtraMatchTest)matchFqdnIp, (void **)&fqdnFoundMapping, &isEntryFound);
                if (!isEntryFound)
                {
                    /* Add new entry in FQDN Mapping hash table */
                    status = HASH_TABLE_addPtr(m_hashTableFqdnMapping, ipListhashValue, fqdnMapping);
                    if (OK > status)
                        goto exit;
                }
                else
                {
                    /* Configuration error - conflicting IP is configured in two FQDN groups */
                    status = ERR_IPSEC_SCRIPT_SYNTAX_ERROR;
                    DEBUG_PRINT2(DEBUG_CUSTOM, (sbyte *)"\nInvalid configuration, Conflicting IP is configured"
                        " in FQDN group - ", pxConf->fqdn);
                    goto exit;
                }
                listIndex++;
            }
        }
    }

exit:
	return status;
} /* addFqdnMappingInHash */
#endif


/*------------------------------------------------------------------*/
#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_confAdd1_ex(IPSECCONF pxConf)
#else
extern sbyte4
IPSEC_confAdd1(IPSECCONF pxConf)
#endif
{
    MSTATUS status;
    sbyte4 j, k;

    /* check SP configuration */
    if (IPSEC_SPD_MAX < pxConf->index)
    {
        status = ERR_IPSECCONF_INDEX;
        goto exit;
    }

#ifndef __ENABLE_IPSEC_INTERFACE_ID__
    if (pxConf->ifid)
    {
        status = ERR_IPSECCONF_INTF_ID;
        goto exit;
    }
#endif

    switch (pxConf->oAction)
    {
    case IPSEC_ACTION_BYPASS :
    case IPSEC_ACTION_DROP :
        switch (pxConf->oDir & 0x0f)
        {
        case IPSEC_DIR_INBOUND :
        case IPSEC_DIR_OUTBOUND :
            break;
        default :
            status = ERR_IPSECCONF_DIR;
            goto exit;
        }
        break;
    case IPSEC_ACTION_APPLY :
    case IPSEC_ACTION_PERMIT :
    {
        ubyte oSaLen = pxConf->oSaLen;
        if (IPSEC_NEST_MAX < oSaLen)
        {
            status = ERR_IPSECCONF_BUNDLE;
            goto exit;
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        /* check mode */
        switch (pxConf->oMode)
        {
        case IPSEC_MODE_TUNNEL :
#ifdef __ENABLE_IPSEC_NULL_TUNNEL__
            break;
#endif
        case IPSEC_MODE_TRANSPORT :
        case IPSEC_MODE_DONTCARE : /* 0 */
            if (0 == oSaLen)
            {
                status = ERR_IPSECCONF_BUNDLE;
                goto exit;
            }
            break;
        default : /* invalid */
            status = ERR_IPSECCONF_MODE;
            goto exit;
        }
#else
        if (0 == oSaLen)
        {
            status = ERR_IPSECCONF_BUNDLE;
            goto exit;
        }
        if (IPSEC_MODE_TUNNEL == pxConf->oMode)
        {
            status = ERR_IPSECCONF_MODE;
            goto exit; /* jic */
        }
#endif

        /* check SA info's */
        for (j=0; j < oSaLen; j++)
        {
            struct sainfo *si = &(pxConf->pxSa[j]);

            ubyte oSecuProto = si->oSecuProto;
            ubyte oAuthAlgo = si->oAuthAlgo;
            ubyte oEncrAlgo = si->oEncrAlgo;
            ubyte2 wKeyLen = si->oEncrKeyLen;
            ubyte aeadTag = si->aeadTag;

            /* check protocol & auth algo */
            switch (oSecuProto)
            {
            case IPSEC_PROTO_ESP :
                /*if (oAuthAlgo)
                {
                    status = ERR_IPSECCONF_AUTH_ALGO;
                    goto exit;
                }*/
                break;
            case IPSEC_PROTO_ESP_AUTH :
            case IPSEC_PROTO_ESP_NULL :
            case IPSEC_PROTO_AH :
                if (oAuthAlgo && !IPSEC_hmacSuite(oAuthAlgo))
                {
                    status = ERR_IPSECCONF_AUTH_ALGO;
                    goto exit; /* unknown */
                }
                break;
            default : /* unsupported */
                status = ERR_IPSECCONF_PROTOCOL;
                goto exit;
            }

            /* check encr algo */
            switch (oSecuProto)
            {
            case IPSEC_PROTO_ESP :
            case IPSEC_PROTO_ESP_AUTH :
                if (oEncrAlgo || wKeyLen
                              || aeadTag)
                    break;
/*          case IPSEC_PROTO_ESP_NULL :
            case IPSEC_PROTO_AH :*/
            default :
                continue;
            }

            for (k=0; ; k++)
            {
                AeadAlgo *pAeadAlgo;

                SADB_cipherSuiteInfo *pCipherSuite = IPSEC_getCipherSuite(k);
                if (!pCipherSuite)
                {
                    status = ERR_IPSECCONF_ENCR_ALGO;
                    goto exit; /* no matching cipher */
                }

                if (oEncrAlgo && /* encr algo */
                    (oEncrAlgo != pCipherSuite->oEncrAlgo))
                    continue;

                pAeadAlgo = pCipherSuite->pAeadAlgo;

                if (aeadTag) /* specific tag size */
                {
                    if ((NULL == pAeadAlgo) || /* non-AEAD algo */
                        (aeadTag != pAeadAlgo->tagSize)) /* mismatch */
                    {
                        continue;
                    }
                }

                if (wKeyLen) /* key-length */
                {
                    ubyte2 wKeyLenMin = pCipherSuite->wKeyLen;
                    ubyte2 wKeyLenMax = pCipherSuite->wKeyLenEnd;

                    /* add 'nonce' length (e.g. AEAD 'salt' or aes-ctr) */
                    ubyte2 wFullKeyLen = wKeyLen
                                       + (ubyte2) pCipherSuite->oNonceLen;

                    if ((wFullKeyLen < wKeyLenMin) ||
                        (wKeyLenMax && (wFullKeyLen > wKeyLenMax)))
                        continue;
                }
#ifndef __ENABLE_DIGICERT_GDOI_CLIENT__
                if ((NULL != pAeadAlgo) &&
                    (IPSEC_PROTO_ESP_AUTH == oSecuProto))
                {
                    /* must not use AEAD encr algo with extra auth */
                    if (oAuthAlgo) continue;

                    if (oEncrAlgo || aeadTag)
                        si->oSecuProto = IPSEC_PROTO_ESP; /* !!! */
                }
#endif
                break; /* match */
            } /* for (k=0; */

        } /* for (j=0; */

        break;
    }

    default : /* invalid */
        status = ERR_IPSECCONF_ACTION;
        goto exit;
    } /* switch */



#ifdef __ENABLE_RB_SADB__
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    /* Update the FQDNMapping hash table for the entire IP list of FQDN */
    if (pxConf->isUnicastGDOI)
    {
        status = addFqdnMappingInHash(pxConf);
        if (OK > status)
        {
            return status;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    /* Store and start and end IP addresses for Unicast range */
    if (pxConf->isGdoi)
    {
        status = addUnicastRange(pxConf);
    }
#endif
#endif

    status = IPSEC_newSp(pxConf);

exit:
    return (sbyte4)status;
} /* IPSEC_confAdd1 */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_confAdd(IPSECCONF axConf, sbyte4 num)
{
    sbyte4 i;
    for (i=0; i < num; i++)
    {
#if defined(__VXWORKS_RTOS__)
        if (OK > IPSEC_confAdd1_ex(axConf + i))
            break;
#else
        if (OK > IPSEC_confAdd1(axConf + i))
            break;
#endif
    }

    return i; /* returns # of SP added */
} /* IPSEC_confAdd */


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_confDelete_ex(IPSECCONF pxConf)
#else
extern sbyte4
IPSEC_confDelete(IPSECCONF pxConf)
#endif
{
    /* Note: IPSEC_confDelete() checks the following fields in 'pxConf':*/
    /*     index (> 0), oAction, oDir                                   */
    MSTATUS status = OK;

    ubyte oAction;
    ubyte oDir;
    intBoolean bMirrored;
    intBoolean bDir[2] = {FALSE, FALSE}; /* inbound/outbound */

    sbyte4 index, i;
    SPD pxSp;

    /* delete specific SPD entry */
    if (0 >= (index = pxConf->index))
    {
        status = ERR_IPSECCONF_INDEX;
        goto exit;
    }

    oAction = pxConf->oAction;
    oDir = (pxConf->oDir & 0x0f);
    bMirrored = (IPSEC_DIR_MIRRORED & (pxConf->oDir & 0xf0)) ? TRUE : FALSE;

    /* get direction(s) */
    switch (oAction)
    {
    case IPSEC_ACTION_PERMIT :
        bDir[0] = TRUE;
        break;
    case IPSEC_ACTION_APPLY :
        bDir[1] = TRUE;
        break;
    case IPSEC_ACTION_BYPASS :
    case IPSEC_ACTION_DROP :
    case 0:
        switch (oDir)
        {
        case 0 :
            bDir[0] = bDir[1] = TRUE;
            break;
        case IPSEC_DIR_INBOUND :
            bDir[0] = TRUE;
            break;
        case IPSEC_DIR_OUTBOUND :
            bDir[1] = TRUE;
            break;
        default :
            status = ERR_IPSECCONF_DIR;
            goto exit;
        }
        break;
    default :
        status = ERR_IPSECCONF_ACTION;
        goto exit;
    }

    /* delete specific SPD entry */
    for (i=0; i < 2; i++)
    {
        if (!bDir[i]) continue;

        if (NULL != (pxSp = IPSEC_indexSp(index, (0==i))))
        {
            if ((0 == oAction) || (oAction == pxSp->oAction))
            {
                if (bMirrored && (IPSEC_SP_FLAG_MIRRORED & pxSp->flags)) /* do this first */
                {
                    SPD pxSpM;
                    if (NULL != (pxSpM = IPSEC_indexSp(index, (0!=i))))
                    {
                        IPSEC_delSp(pxSpM);
                    }
                }
                status = IPSEC_delSp(pxSp);
            }
        }
    } /* for */

exit:
    return (sbyte4)status;
} /* IPSEC_confDelete */


/*------------------------------------------------------------------*/

#if defined(__VXWORKS_RTOS__)
extern sbyte4
IPSEC_confFlush_ex(void)
#else
extern sbyte4
IPSEC_confFlush(void)
#endif
{
    MSTATUS status = OK;

    SPD pxSp = NULL;
    while (NULL != (pxSp = IPSEC_enumSp(pxSp)))
        status = IPSEC_delSp(pxSp);

    return (sbyte4)status;
} /* IPSEC_confFlush */


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) */

