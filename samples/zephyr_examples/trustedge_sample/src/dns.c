#include <stdint.h>
#include "dns.h"

DnsLookupEntry lookup_table[MAX_LOOKUPS];

void dnsLookupTableInit() {
    for(int i = 0; i < MAX_LOOKUPS; i++) {
        lookup_table[i].status = DNS_SLOT_OPEN;
        k_mutex_init(&(lookup_table[i].lock));
    }
}

#define DNS_TIMEOUT (5 * MSEC_PER_SEC)

void dns_result_cb(enum dns_resolve_status status,
		   struct dns_addrinfo *info,
		   void *user_data)
{
	char *hr_family;
	void *addr;
    int index = (int)(intptr_t)user_data;
    DnsLookupEntry *pEntry = &lookup_table[index];

	printk("lookup table index=%d\n", index);
	switch (status) {
	case DNS_EAI_CANCELED:
		printk("DNS query was canceled\n");
		return;
	case DNS_EAI_FAIL:
		printk("DNS resolve failed\n");
		return;
	case DNS_EAI_NODATA:
		printk("Cannot resolve address\n");
		return;
	case DNS_EAI_ALLDONE:
		printk("DNS resolving finished\n");
        k_sem_give(&(pEntry->semaphore));
		return;
	case DNS_EAI_INPROGRESS:
		break;
	default:
		printk("DNS resolving error (%d)\n", status);
		return;
	}

	if (!info) {
		return;
	}

	if (info->ai_family == AF_INET) {
		hr_family = "IPv4";
		addr = &net_sin(&info->ai_addr)->sin_addr;
	} else if (info->ai_family == AF_INET6) {
		hr_family = "IPv6";
		addr = &net_sin6(&info->ai_addr)->sin6_addr;
	} else {
		printk("Invalid IP address family %d\n", info->ai_family);
		return;
	}

    k_mutex_lock(&(pEntry->lock), K_FOREVER);
    net_addr_ntop(info->ai_family, addr, pEntry->ip, IP_MAX);
    pEntry->status = DNS_RESOLVED;
    k_mutex_unlock(&(pEntry->lock));
}

int startDnsLookup(char *pName, char *pIPStr)
{
    int ret;
    int i;

    if (NULL == pName || NULL == pIPStr)
    {
        return -1;
    }

    if ((strcmp(pName, "localhost") == 0) || (strcmp(pName, "provision.digicert.com") == 0))
    {
        strcpy(pIPStr, "172.18.209.115");
        return 0;
    }

    /* is pNamed already cached? */
    for (i = 0; i < MAX_LOOKUPS; i++)
    {
        k_mutex_lock(&(lookup_table[i].lock), K_FOREVER);
        if ((lookup_table[i].status == DNS_RESOLVED) &&
            (strncmp(lookup_table[i].hostname, pName, HOSTNAME_MAX) == 0))
        {
            strncpy(pIPStr, lookup_table[i].ip, IP_MAX);
            printk("%s IPv4 address: %s\n", pName, pIPStr);
            k_mutex_unlock(&(lookup_table[i].lock));
            return 0;
        }
        k_mutex_unlock(&(lookup_table[i].lock));
    }

    for (i = 0; i < MAX_LOOKUPS; i++)
    {
        k_mutex_lock(&(lookup_table[i].lock), K_FOREVER);
        if (DNS_SLOT_OPEN == lookup_table[i].status)
        {
            k_sem_init(&(lookup_table[i].semaphore), 0, 1);
            strncpy(lookup_table[i].hostname, pName, HOSTNAME_MAX - 1);
            lookup_table[i].hostname[HOSTNAME_MAX - 1] = '\0';
            ret = dns_get_addr_info(pName,
                    DNS_QUERY_TYPE_A,
                    NULL,
                    dns_result_cb,
                    (void *)(intptr_t)i,
                    DNS_TIMEOUT);
            if (ret == 0) {
                lookup_table[i].status = DNS_PENDING;
            } else {
                printk("Cannot resolve IPv4ress (%d)\n", ret);
                k_sem_give(&(lookup_table[i].semaphore));
            }
            k_mutex_unlock(&(lookup_table[i].lock));
            break;
        }
        k_mutex_unlock(&(lookup_table[i].lock));
    }

    if (i >= MAX_LOOKUPS) {
        printk("DNS lookup table full\n");
        return -ENOMEM;
    }

    /* wait for signal that lookup is complete or timed out */
    k_sem_take(&(lookup_table[i].semaphore), K_MSEC(DNS_TIMEOUT));
    k_mutex_lock(&(lookup_table[i].lock), K_FOREVER);
    else
    {
        printk("DNS lookup for %s IPv4 address failed\n", pName);
        lookup_table[i].status = DNS_SLOT_OPEN;
        lookup_table[i].hostname[0] = '\0';
        lookup_table[i].ip[0] = '\0';
    }

    k_mutex_unlock(&(lookup_table[i].lock));
    return ret;
}
