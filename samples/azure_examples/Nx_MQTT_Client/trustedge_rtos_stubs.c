/*
 * trustedge_rtos_stubs.c
 *
 * ThreadX/AzureRTOS stubs for TrustCore SDK symbols that are not mapped
 * for ThreadX in the SDK's RTOS/TCP/FMGMT abstraction layers.
 *
 * These symbols are required by the linker but either:
 *  - run on a code path never reached during MQTT cert enrollment, or
 *  - have a natural ThreadX equivalent wired here.
 */

#include "tx_api.h"
#include "nxd_dns.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "moptions.h"
#include "mdefs.h"
#include "mtypes.h"
#include "merrors.h"
#include "mrtos.h"
#include "mstdlib.h"

extern NX_DNS DnsClient;   /* defined in app_netxduo.c */

/* ── TCP_INIT / TCP_SHUTDOWN ─────────────────────────────────────────────── */
/* NetX Duo is already running when TrustCore is initialised; these are       */
/* no-ops.  initmocana.c calls TCP_INIT during DIGICERT_initialize().         */
MSTATUS TCP_INIT(void)    { return OK; }
MSTATUS TCP_SHUTDOWN(void){ return OK; }

/* ── TCP_GETHOSTBYNAME ───────────────────────────────────────────────────── */
/* Called by trustedge_utils.c TRUSTEDGE_utilsGetHostByName().                */
MSTATUS TCP_GETHOSTBYNAME(char *pDomainName, char *pIpAddress)
{
    ULONG ip_addr = 0;
    UINT  ret;

    if (!pDomainName || !pIpAddress)
        return ERR_NULL_POINTER;

    ret = nx_dns_host_by_name_get(&DnsClient,
                                  (UCHAR *)pDomainName,
                                  &ip_addr,
                                  NX_IP_PERIODIC_RATE * 10);   /* 10-second timeout */
    if (ret != NX_SUCCESS)
        return ERR_TCP_CONNECT_ERROR;

    snprintf(pIpAddress, 16, "%lu.%lu.%lu.%lu",
             (ip_addr >> 24) & 0xFFUL,
             (ip_addr >> 16) & 0xFFUL,
             (ip_addr >>  8) & 0xFFUL,
              ip_addr        & 0xFFUL);
    return OK;
}

/* ── KEYGEN_getPassword ──────────────────────────────────────────────────── */
/* Only reached when gGetSigningKeyPw or gProtected flags are set, which     */
/* never happens in the embedded MQTT enrollment path (keys are always       */
/* generated without passphrases on bare-metal targets).                     */
MSTATUS KEYGEN_getPassword(ubyte **ppRetPassword, ubyte4 *pRetPasswordLen,
                            char *pPwName, char *pFileName)
{
    (void)pPwName;
    (void)pFileName;
    if (ppRetPassword)    *ppRetPassword    = NULL;
    if (pRetPasswordLen)  *pRetPasswordLen  = 0;
    return ERR_UNSUPPORTED_OPERATION;
}
