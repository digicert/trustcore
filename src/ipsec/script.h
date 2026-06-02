/**
 * @file  script.h
 * @brief NanoSec IPsec policy script parsing functions API.
 *
 * @details    This file contains NanoSec IPsec policy script parsing function
 *             declarations.
 * @since      1.41
 * @version    6.4 and later
 *
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


/*------------------------------------------------------------------*/

#ifndef __SCRIPT_HEADER__
#define __SCRIPT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "../ipsec/ipsecconf.h"

/**
@brief      Read a security policy configuration script and configure
            corresponding NanoSec IPsec policies.

@details    This function reads a security policy configuration script and
            configures corresponding NanoSec IPsec policies that will be
            applied to IP packets.

This is an easier to use alternative to building the necessary structures within
your application code and making calls to IPSEC_confAdd(). For details about the
policy script format, see @ref ipsec_policy_scripts.

@ingroup    ipsec_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_IPSEC_SERVICE__

@param scriptContent    Pointer to character stream containing the policy
                        script.

@inc_file script.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa     For details about the policy script format, see @ref ipsec_policy_scripts.

@funcdoc    script.h
*/

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
#define MAX_HOST_IP 2

#define MOC_IS_IP_PART_OF_GROUP(ipAddr, fqdn_name, isIpFound)\
            ubyte4 ipListIndex=0, fqdnListIndex=0;\
            isIpFound = FALSE;\
            while(fqdnListIndex < m_groupListCount){\
                if(0 == DIGI_STRCMP((sbyte *)m_fqdnGroupList[fqdnListIndex].fqdnName,(sbyte *)fqdn_name)){\
                    while(ipListIndex < m_fqdnGroupList[fqdnListIndex].ipListCount){\
                        if(m_fqdnGroupList[fqdnListIndex].IPDomainList[ipListIndex].unicastIPAddr == ipAddr){\
                            isIpFound = TRUE;\
                            break;}\
                        ipListIndex++;}\
                    break;}\
                fqdnListIndex++;}\

#define MOC_FQDN_IP_ADDR(fqdnListIndex, ipListIndex)\
    m_fqdnGroupList[fqdnListIndex].IPDomainList[ipListIndex].unicastIPAddr\

#define MOC_GROUP_FIND_FQDN(fqdn_name, fqdnIndex, isFqdnFound)\
            ubyte4 fqdnListIndex=0;\
            isFqdnFound = FALSE;\
            while(fqdnListIndex < m_groupListCount){\
                if(0 == DIGI_STRCMP((sbyte *)m_fqdnGroupList[fqdnListIndex].fqdnName,(sbyte *)fqdn_name)){\
                    isFqdnFound = TRUE;\
                    fqdnIndex = fqdnListIndex;\
                    break;}\
                fqdnListIndex++;}\

#endif

#define MOC_COMPARE_IP_LIST(ipList1, ipCount1, ipList2, ipCount2, isEqual)\
            ubyte4 ipListIndex1 = 0, ipListIndex2 = 0;\
            isEqual = FALSE;\
            if(ipCount1 != ipCount2){\
                isEqual = FALSE;}\
            else{\
                while(ipListIndex1 < ipCount1){\
                    ipListIndex2 = 0;\
                    isEqual = FALSE;\
                    while(ipListIndex2 < ipCount1){\
                        if(ipList1[ipListIndex1] == ipList2[ipListIndex2]){\
                            isEqual = TRUE;\
                            break;}\
                        ipListIndex2++;}\
                    if(FALSE == isEqual){\
                        break;}\
                    ipListIndex1++;}}\



/**
*/
typedef struct IPToDomainMappingList {

   MOC_IP_ADDRESS unicastIPAddr;
   ubyte* domainName;
   ubyte4 operationFlag;
}IPToDomainMappingList;

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
/**
*/
typedef struct fqdnUnicastGroupConfig {

    ubyte fqdnName[MOC_MAX_FQDN_LEN];
    ubyte4 hostIp[MAX_HOST_IP];
    ubyte4 hostIPCount;
    ubyte4 ipListCount;
    IPToDomainMappingList IPDomainList[MAX_IP_IN_FQDN];
} fqdnUnicastGroupConfig;

MOC_EXTERN intBoolean DIGI_find_fqdn(MOC_IP_ADDRESS ipAddr, char * fqdn);

MOC_EXTERN MSTATUS
#if !(defined(__ENABLE_DIGICERT_64_BIT__) && defined(__ENABLE_DIGICERT_IPV6__))
addIpListInGroup(char* fqdnName, ubyte4 ipList[], ubyte4* ipCount);
#else
addIpListInGroup(char* fqdnName, ubyte8 ipList[], ubyte4* ipCount);
#endif
#endif /* __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__ */

MOC_EXTERN MSTATUS IPSEC_ParseScript(const sbyte* scriptContent, ubyte parse_only, sbyte** hostIpAddr);

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
MOC_EXTERN MSTATUS validateSecurityPolicy(struct ipsecKeyEx *keyEx);
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* __SCRIPT_HEADER__ */

