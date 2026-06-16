#ifndef DIGI_DNS_SAMPLE_H
#define DIGI_DNS_SAMPLE_H

#include <zephyr/net/dns_resolve.h>
#include <zephyr/kernel.h>

#define MAX_LOOKUPS     8
#define HOSTNAME_MAX    DNS_MAX_NAME_SIZE
#define IP_MAX          40

typedef enum {
    DNS_SLOT_OPEN = -1,
    DNS_PENDING,
    DNS_RESOLVED
} DnsStatus;

typedef struct {
    char hostname[HOSTNAME_MAX];
    char ip[IP_MAX];
    DnsStatus status;
    struct k_mutex lock;
    struct k_sem semaphore; /* used to signal lookup is complete */
} DnsLookupEntry;

void dnsLookupTableInit(void);

/* extern used API */
int startDnsLookup(char *pName, char *pIPStr);

#endif