/*
 * if_mapping.h
 *
 * IP interface mapping definitions
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

#ifndef __IP_MAPPING_H__
#define __IP_MAPPING_H__

#include "../common/moptions.h"

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/mem_pool.h"
#include "../common/random.h"
#include "../crypto/crypto.h"

#ifdef __RTOS_LINUX__
#include <linux/types.h>
#include <linux/ip.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define STORE_LEN 20
#define PORT_KEY_LEN 32
#ifdef __RTOS_WIN32__
#define IF_SIZE 128
#else
#define IF_SIZE 16
#endif

/* Maximum number of entries in address_translation.conf */
#define MAX_NUM_ADDRESS_TRANSLATION 8

/* Maximum number of entries in port_mapping.conf */
#ifndef MAX_PORTS_PER_POLICY
#define MAX_PORTS_PER_POLICY 32
#endif
/*#pragma pack(1)*/
typedef union _ifmap_addr
{
    ubyte4     v4;             /**< The IPv4 address */
    ubyte      v6[16];         /**< The IPv6 address */
} ifmap_addr;

typedef struct _ipsec_portlist
{
    char key[PORT_KEY_LEN];
    ubyte2 port_mapping_list[MAX_PORTS_PER_POLICY];
    ubyte4 port_mapping_count;
} ipsec_portlist;

typedef struct _ifmap_element {
    ifmap_addr broadcast_address;
    unsigned char smac[6];
    unsigned char dmac[6];
    char if_name[IF_SIZE + 4];
#ifdef __RTOS_WIN32__
    void * adapter_handle;
    sbyte adapter_name[IF_SIZE + 4];
#endif
    ubyte2 port_mapping_list[MAX_PORTS_PER_POLICY];
    ubyte4 port_mapping_count;
    ubyte drop_original_pkt;
#ifdef __RTOS_LINUX__
    ubyte2 mtu;
#endif
    ifmap_addr multicast_address;
} ifmap_element;

typedef struct _ifmap_entry {
    MSTATUS status;
    int count;
    int af;
    ifmap_element element[STORE_LEN];
} ifmap_entry;


MOC_EXTERN MSTATUS create_ifmap(sbyte *addrTransFile);
MOC_EXTERN void get_ifmap(ifmap_entry *ifmap);
MOC_EXTERN MSTATUS read_portmapping(sbyte *addrTransFile, ifmap_entry *ifmap);
MOC_EXTERN MSTATUS multicast_close_ipv4(void);
MOC_EXTERN int get_interface_index(char *hostIp);
MOC_EXTERN MSTATUS read_portlist_from_file(sbyte *portListFile);
#ifdef __cplusplus
}
#endif
#endif  /* __IP_MAPPING_H__ */
