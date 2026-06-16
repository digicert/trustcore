#include <zephyr/kernel.h>
#include <zephyr/multi_heap/shared_multi_heap.h>
#include <zephyr/logging/log.h>

#define __RTOS_ZEPHYR__
#define __RTOS_LINUX__

#include <string.h>
#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void __real_free(void *ptr);
extern MSTATUS __real_TRUSTEDGE_utilsGetHostByName(signed char *pName, signed char *pIpStr);

#define SPIRAM_THRESHOLD 2
#define MAX_TRACKED_ALLOCS 10000

static volatile uint32_t total_mallocs = 0;
static volatile uint32_t total_frees = 0;
static volatile uint32_t tracking_failures = 0;

__attribute__((section(".ext_ram.bss")))
static volatile struct
{
    void *ptr;
    uint32_t magic;
} alloc_tracking[MAX_TRACKED_ALLOCS];

#define SPIRAM_MAGIC 0xDEADBEEF
#define DRAM_MAGIC   0xCAFEBABE
#define SLOT_DELETED ((void*)1)
#define SPIRAM_DEBUG_LOG 0

static struct k_spinlock tracking_lock;

static inline bool is_spiram_ptr(void *ptr)
{
    if (!ptr)
    {
        return false;
    }

    uintptr_t addr = (uintptr_t)ptr;
    return (addr >= 0x3c000000 && addr < 0x3e000000);
}

static void track_allocation(void *ptr, bool is_spiram) {
    if (!ptr)
    {
        return;
    }

    if (k_is_in_isr())
    {
        return;
    }

    total_mallocs++;

    k_spinlock_key_t key = k_spin_lock(&tracking_lock);

    uint32_t hash = ((uintptr_t)ptr >> 3) % MAX_TRACKED_ALLOCS;
    uint32_t attempts = 0;

    while (attempts < MAX_TRACKED_ALLOCS)
    {
        if (alloc_tracking[hash].ptr == NULL || alloc_tracking[hash].ptr == SLOT_DELETED)
        {
            alloc_tracking[hash].ptr = ptr;
            alloc_tracking[hash].magic = is_spiram ? SPIRAM_MAGIC : DRAM_MAGIC;
            k_spin_unlock(&tracking_lock, key);
            return;
        }

        hash = (hash + 1) % MAX_TRACKED_ALLOCS;
        attempts++;
    }

    tracking_failures++;
#if SPIRAM_DEBUG_LOG
    printk("Tracking table full, allocation %p not tracked (failures: %u)\n", ptr, tracking_failures);
#endif
    k_spin_unlock(&tracking_lock, key);
}

static bool find_and_remove_allocation(void *ptr) {
    if (!ptr)
    {
        return false;
    }

    if (k_is_in_isr())
    {
        return is_spiram_ptr(ptr);
    }

    total_frees++;

    k_spinlock_key_t key = k_spin_lock(&tracking_lock);

    uint32_t hash = ((uintptr_t)ptr >> 3) % MAX_TRACKED_ALLOCS;
    uint32_t attempts = 0;

    while (attempts < MAX_TRACKED_ALLOCS)
    {
        if (alloc_tracking[hash].ptr == ptr)
        {
            bool was_spiram = (alloc_tracking[hash].magic == SPIRAM_MAGIC);
            alloc_tracking[hash].ptr = SLOT_DELETED;
            alloc_tracking[hash].magic = 0;
            k_spin_unlock(&tracking_lock, key);
            return was_spiram;
        }

        if (alloc_tracking[hash].ptr == NULL)
        {
            break;
        }

        hash = (hash + 1) % MAX_TRACKED_ALLOCS;
        attempts++;
    }

    k_spin_unlock(&tracking_lock, key);

    bool is_spiram = is_spiram_ptr(ptr);
#if SPIRAM_DEBUG_LOG
    printk("Allocation %p not tracked, using address check: %s (mallocs: %u, frees: %u)\n",
            ptr, is_spiram ? "SPIRAM" : "DRAM", total_mallocs, total_frees);
#endif
    return is_spiram;
}

void *__wrap_malloc(size_t size)
{
    void *ptr = NULL;
    if (size == 0)
    {
        return NULL;
    }

    ptr = shared_multi_heap_alloc(SMH_REG_ATTR_EXTERNAL, size);
    if (ptr)
    {
        track_allocation(ptr, true);
#if SPIRAM_DEBUG_LOG
        printk("SPIRAM malloc: %p (%zu bytes)\n", ptr, size);
#endif
        return ptr;
    }

    ptr = __real_malloc(size);
    if (ptr)
    {
        track_allocation(ptr, false);
#if SPIRAM_DEBUG_LOG
        printk("DRAM malloc: %p (%zu bytes)\n", ptr, size);
#endif
    }
    else
    {
#if SPIRAM_DEBUG_LOG
        printk("malloc failed for %zu bytes\n", size);
#endif
    }

    return ptr;
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    void *ptr = NULL;
    if (nmemb == 0 || size == 0)
    {
        return NULL;
    }

    if (nmemb > SIZE_MAX / size)
    {
#if SPIRAM_DEBUG_LOG
        printk("calloc overflow: %zu * %zu\n", nmemb, size);
#endif
        return NULL;
    }

    size_t total_size = nmemb * size;

    ptr = shared_multi_heap_alloc(SMH_REG_ATTR_EXTERNAL, total_size);
    if (ptr)
    {
        memset(ptr, 0, total_size);
        track_allocation(ptr, true);
#if SPIRAM_DEBUG_LOG
        printk("SPIRAM calloc: %p (%zu bytes)\n", ptr, total_size);
#endif
        return ptr;
    }

    ptr = __real_calloc(nmemb, size);
    if (ptr)
    {
        track_allocation(ptr, false);
#if SPIRAM_DEBUG_LOG
        printk("DRAM calloc: %p (%zu bytes)\n", ptr, total_size);
#endif
    }
    else
    {
#if SPIRAM_DEBUG_LOG
        printk("calloc failed for %zu bytes\n", total_size);
#endif
    }

    return ptr;
}

void __wrap_free(void *ptr)
{
    if (!ptr)
    {
        return;
    }

    bool was_spiram = find_and_remove_allocation(ptr);

    if (was_spiram)
    {
        shared_multi_heap_free(ptr);
#if SPIRAM_DEBUG_LOG
        printk("SPIRAM free: %p\n", ptr);
#endif
    }
    else
    {
        __real_free(ptr);
#if SPIRAM_DEBUG_LOG
        printk("DRAM free: %p\n", ptr);
#endif
    }
}

MSTATUS __wrap_TRUSTEDGE_utilsGetHostByName(signed char *hostname, signed char *addr)
{
    MSTATUS status = OK;
    if (hostname && strcmp(hostname, "provision.digicert.com") == 0) {
        const char *configured_ip = CONFIG_NET_CONFIG_PEER_IPV4_ADDR;

        if (!configured_ip || strlen(configured_ip) == 0) {
            return __real_TRUSTEDGE_utilsGetHostByName(hostname, addr);
        }

        strcpy(addr, configured_ip);
        return status;
    }

    return __real_TRUSTEDGE_utilsGetHostByName(hostname, addr);
}
