/* msg_logger.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */
#ifdef __RTOS_ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(trustedge, LOG_LEVEL_DBG);
#endif

#include "../common/moptions.h"
#ifdef __RTOS_LINUX__
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#endif

#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
#include <stdarg.h>
#endif

#if defined(__ENABLE_DIGICERT_MSG_LOG__)

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/msg_logger.h"

#define MAX_LOG_LEVEL           MSG_LOG_NONE

static char* gpLevelStrings[] = {
    "VERBOSE",
    "INFO",
    "DEBUG",
    "WARNING",
    "ERROR",
    "NONE"
};

#ifdef __RTOS_ZEPHYR__
static atomic_t gIsLogLevelSet = ATOMIC_INIT((int) FALSE);
static atomic_t gLevel = ATOMIC_INIT((int) MSG_LOG_NONE);
#else
static RTOS_MUTEX gpLogMutex = NULL;
static sbyte *gpLabel = NULL;
static MsgLogLevel gLevel = MSG_LOG_NONE;
static intBoolean gIsLogLevelSet = FALSE;
#endif

extern MSTATUS MSG_LOG_init(MsgLogLevel level)
{
    MSTATUS status;

#ifdef __RTOS_ZEPHYR__
    if (TRUE == (intBoolean) atomic_get(&gIsLogLevelSet))
#else
    if (TRUE == gIsLogLevelSet)
#endif
    {
        status = MSG_LOG_changeLevel(level);
        goto exit;
    }

    if (MAX_LOG_LEVEL < level)
    {
        status = ERR_MSG_LOG_LEVEL_INVALID;
        goto exit;
    }

#ifdef __RTOS_ZEPHYR__
    status = OK;
    atomic_set(&gLevel, level);
    atomic_set(&gIsLogLevelSet, TRUE);
#else
    status = RTOS_mutexCreate(&gpLogMutex, 0, 0);
    if (OK != status)
    {
        goto exit;
    }

    gLevel = level;
    gIsLogLevelSet = TRUE;
#endif

exit:

    return status;
}

extern void MSG_LOG_uninit(void)
{
#ifdef __RTOS_ZEPHYR__
    atomic_set(&gIsLogLevelSet, FALSE);
    atomic_set(&gLevel, MSG_LOG_NONE);
#else
    (void) RTOS_mutexFree (&gpLogMutex);
    gpLabel = NULL;
    gIsLogLevelSet = FALSE;
    gLevel = MSG_LOG_NONE;
#endif
}

extern intBoolean MSG_LOG_isLogLevelSet(void)
{
#ifdef __RTOS_ZEPHYR__
    return (intBoolean) atomic_get(&gIsLogLevelSet);
#else
    return gIsLogLevelSet;
#endif
}

extern MSTATUS MSG_LOG_changeLevel(MsgLogLevel level)
{
    MSTATUS status;

#ifndef __RTOS_ZEPHYR__
    RTOS_mutexWait(gpLogMutex);
#endif

    if (MAX_LOG_LEVEL < level)
    {
        status = ERR_MSG_LOG_LEVEL_INVALID;
        goto exit;
    }

#ifdef __RTOS_ZEPHYR__
    atomic_set(&gLevel, level);
#else
    gLevel = level;
#endif
    status = OK;

exit:

#ifndef __RTOS_ZEPHYR__
    RTOS_mutexRelease(gpLogMutex);
#endif

    return status;
}

extern MsgLogLevel MSG_LOG_getLevel(void)
{
#ifdef __RTOS_ZEPHYR__
    return (MsgLogLevel) atomic_get(&gLevel);
#else
    return gLevel;
#endif
}

extern MSTATUS MSG_LOG_convertStringLevel(
    sbyte *pLevelStr,
    MsgLogLevel *pLevel)
{
    MSTATUS status;
    ubyte4 i;

    if (NULL == pLevelStr || NULL == pLevel)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = 0; i < COUNTOF(gpLevelStrings); i++)
    {
        if (0 == DIGI_STRCMP((const sbyte *) gpLevelStrings[i], pLevelStr))
            break;
    }

    if (COUNTOF(gpLevelStrings) == i)
    {
        status = ERR_MSG_LOG_LEVEL_STRING_INVALID;
        goto exit;
    }

    *pLevel = (MsgLogLevel) i;
    status = OK;

exit:

    return status;
}

extern void MSG_LOG_setLabel(sbyte *pLabel)
{
#ifndef __RTOS_ZEPHYR__
    RTOS_mutexWait(gpLogMutex);
    gpLabel = pLabel;
    RTOS_mutexRelease(gpLogMutex);
#endif
}

extern byteBoolean MSG_LOG_shouldPrint(MsgLogLevel level)
{
#ifdef __RTOS_ZEPHYR__
    return atomic_get(&gLevel) <= level ? TRUE : FALSE;
#else
    return gLevel <= level ? TRUE : FALSE;
#endif
}

#if !defined(__RTOS_ZEPHYR__)
extern void MSG_LOG_printStartEx(MsgLogLevel level, sbyte *pLabel)
{
#if defined(__RTOS_LINUX__) && defined(__ENABLE_DIGICERT_MSG_LOG_TIMESTAMP__)
    time_t curTime;
    struct tm *timeinfo;
    sbyte timeBuffer[32];
    pid_t pid;

    time(&curTime);
    timeinfo = localtime(&curTime);
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S %Z", timeinfo);

    pid = getpid();
#endif

    RTOS_mutexWait(gpLogMutex);
#if defined(__RTOS_LINUX__) && defined(__ENABLE_DIGICERT_MSG_LOG_TIMESTAMP__)
    DEBUG_CONSOLE_printf("%s [PID %d] ", timeBuffer, pid);
#endif
    if (NULL != pLabel)
        DEBUG_CONSOLE_printf("[%s] ", pLabel);
    DEBUG_CONSOLE_printf("%s: ", gpLevelStrings[level]);
}
#endif /* !__RTOS_ZEPHYR__ */

extern void MSG_LOG_printStart(MsgLogLevel level)
{
#if !defined(__RTOS_ZEPHYR__)
    MSG_LOG_printStartEx(level, gpLabel);
#endif /* !__RTOS_ZEPHYR__ */
}

#if !(!defined(__DIGICERT_DUMP_CONSOLE_TO_STDOUT__) || defined(__QNX_RTOS_SLOG__) || defined(__UCOS_DIRECT_RTOS__) || \
    defined(__UCOS_DIRECT_RTOS__) || defined(__RTOS_ANDROID__) || defined(__KERNEL__))
extern void DEBUG_CONSOLE_printfVarList(const char *format, va_list ap);
#endif

void MSG_LOG_printfVarList(const char *format, va_list valist)
{
#if !(!defined(__DIGICERT_DUMP_CONSOLE_TO_STDOUT__) || defined(__QNX_RTOS_SLOG__) || defined(__UCOS_DIRECT_RTOS__) || \
    defined(__UCOS_DIRECT_RTOS__) || defined(__RTOS_ANDROID__) || defined(__KERNEL__))
    DEBUG_CONSOLE_printfVarList(format, valist);
#else
#error "MSG_LOG_printfVarList is not implemented for this platform"
#endif
}

extern void MSG_LOG_printStartRaw()
{
#if !defined(__RTOS_ZEPHYR__)
    RTOS_mutexWait(gpLogMutex);
#endif /* !__RTOS_ZEPHYR__ */
}

extern void MSG_LOG_printEnd(void)
{
#if !defined(__RTOS_ZEPHYR__)
    RTOS_mutexRelease(gpLogMutex);
#endif /* !__RTOS_ZEPHYR__ */
}

extern void MSG_LOG_printHexBuffer(ubyte *pBuffer, ubyte4 bufferLen)
{
    ubyte4 i;

    for (i = 0; i < bufferLen; i++)
    {
        DEBUG_CONSOLE_printf("%02X", pBuffer[i]);
    }
}

#ifdef __RTOS_ZEPHYR__
extern void MSG_LOG_printHexBufferEx(MsgLogLevel level, ubyte *pBuffer, ubyte4 bufferLen)
{
    if (!MSG_LOG_shouldPrint(level)) {
        return;
    }

    switch(level)
    {
        case MSG_LOG_VERBOSE:
        case MSG_LOG_INFO:
            LOG_HEXDUMP_INF(pBuffer, bufferLen, "");
            break;
        case MSG_LOG_DEBUG:
            LOG_HEXDUMP_DBG(pBuffer, bufferLen, "");
            break;
        case MSG_LOG_WARNING:
            LOG_HEXDUMP_WRN(pBuffer, bufferLen, "");
            break;
        case MSG_LOG_ERROR:
            LOG_HEXDUMP_ERR(pBuffer, bufferLen, "");
            break;
        case MSG_LOG_NONE:
        default:
            break;
    };
}

void MSG_LOG_printf(MsgLogLevel level, sbyte *pFormat, ...)
{
    va_list args;
    char pBuf[256];
    int ret;

    if (NULL == pFormat)
    {
        return;
    }

    if (!MSG_LOG_shouldPrint(level)) {
        return;
    }

    va_start(args, pFormat);
    ret = vsnprintf(pBuf, sizeof(pBuf), pFormat, args);
    if (ret <= 0)
        return;

    switch(level)
    {
        case MSG_LOG_VERBOSE:
        case MSG_LOG_INFO:
            /* Debug is highest level of debugging in zephyr */
            LOG_DBG("%s", pBuf);
            break;
        case MSG_LOG_DEBUG:
            LOG_INF("%s", pBuf);
            break;
        case MSG_LOG_WARNING:
            LOG_WRN("%s", pBuf);
            break;
        case MSG_LOG_ERROR:
            LOG_ERR("%s", pBuf);
            break;
        case MSG_LOG_NONE:
        default:
            break;
    };

    va_end(args);
}
#endif /* !__RTOS_ZEPHYR__ */

#endif /* __ENABLE_DIGICERT_MSG_LOGGER__ */
