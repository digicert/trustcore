/*
 * build_info.h — stub for ThreadX/STM32 build
 *
 * TrustEdge source files include this header for build-metadata macros.
 * On embedded targets the macros are either unused or replaced by empty
 * definitions so the SDK compiles without a dedicated build system.
 */

#ifndef __BUILD_INFO_HEADER__
#define __BUILD_INFO_HEADER__

#define TRUSTEDGE_BUILD_VERSION     "embedded"
#define TRUSTEDGE_BUILD_DATE        "unknown"
#define TRUSTEDGE_BUILD_COMMIT      "unknown"
#define TRUSTEDGE_BUILD_BRANCH      "unknown"

/* BUILD_INFO_VERSION_VAL: consumed directly by trustedge_agent_main.c and
 * trustedge_agent_attributes.c — must be a string literal expression.     */
#define BUILD_INFO_VERSION_VAL      TRUSTEDGE_BUILD_VERSION

/* BUILD_INFO_print: no-op on embedded targets (only called outside
 * __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__ which we define).            */
#define BUILD_INFO_print()          ((void)0)

/* pthread_join prototype for ThreadX/AzureRTOS targets.
 * Linux and FreeRTOS-ESP32 get it from their own <pthread.h> include.
 * Implementation: the stub in syscalls.c (body is unreachable at runtime
 * because the device is PROVISIONED, never PREINSTALL).                   */
#if !defined(__RTOS_LINUX__) && !(defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
int pthread_join(unsigned long thread, void **retval);
#endif

#endif /* __BUILD_INFO_HEADER__ */
