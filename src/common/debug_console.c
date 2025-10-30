/*
 * debug_console.c
 *
 * Mocana Debug Console
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#if defined (__RTOS_THREADX__) && defined(_RENESAS_SYNERGY_)
#include <app_common.h>
#endif
#if !defined(__KERNEL__) && defined(__ENABLE_MOCANA_PRINTF__)
/* jic - vprintf, vfprintf, vsnprintf not supported */
#include "../common/moc_segment.h"
#include "../common/mprintf.h"
#endif
#include "../common/debug_console.h"

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <asm/string.h>
#include <linux/ctype.h>
#elif defined(__RTOS_ANDROID__)
#include <android/log.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#else
#ifndef __RTOS_MQX__
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#ifdef __ENABLE_MOCANA_PRINTF__
#define MOC_VA_START(a,f) va_start(a.ap, f)
#define MOC_VA_END(a) va_end(a.ap)
#else
typedef va_list moc_va_list;
#define MOC_VA_START(a,f) va_start(a, f)
#define MOC_VA_END(a) va_end(a)
#endif

#endif /* __KERNEL__ */

#ifdef __UCOS_DIRECT_RTOS__
#include <net.h>
#define FILE void *
#endif /* __UCOS_DIRECT_RTOS__ */


/*------------------------------------------------------------------*/

#if !(defined(__KERNEL__) || defined(__MOCANA_DUMP_CONSOLE_TO_STDOUT__))
static intBoolean mBreakServer;
static TCP_SOCKET mSocketConsole;
#endif

/* Make this global to allow caller to test before calling debug function */
sbyte4 m_errorClass = 0xffffffffL; /*!!!! for now turn on all debugging by default */

moctime_t gDbgStartTime;


/*------------------------------------------------------------------*/

static ubyte4
getUpTime(void)
{
#if !defined(__ENABLE_MOCANA_SPLIT_DRIVER__)
    return (RTOS_deltaMS(&gDbgStartTime, NULL));
#else
    return 0;
#endif
}


/*------------------------------------------------------------------*/

#define LOG_BUFSZ 512

#if (!defined(__KERNEL__) && defined(__RTOS_ANDROID__))

#ifdef __ENABLE_DEBUG_TIMESTAMPS__
#include <time.h>
static char g_currtimestring[512];
static RTOS_MUTEX g_logMutex = NULL;

static RTOS_MUTEX getLogMutex()
{
    if (g_logMutex == NULL)
    {
        RTOS_mutexCreate(&g_logMutex, 0, 0);
    }
    return g_logMutex;
}

static char *getcurrtime()
{
    RTOS_mutexWait(getLogMutex());
    g_currtimestring[0] = 0x00;
    struct timeval tv;
    struct tm *ptm;
    gettimeofday(&tv, NULL);
    time_t secs = tv.tv_sec;
    ptm = localtime(&secs);
    char tmp[512];
    strftime(tmp, sizeof(tmp), "%H:%M:%S", ptm);
    long milliseconds = tv.tv_usec/1000;
    (void) snprintf(g_currtimestring, sizeof(g_currtimestring), "%s.%ld", tmp, milliseconds);
    RTOS_mutexRelease(getLogMutex());
    return g_currtimestring;
}

void MOC_logTime(const char *inmsg)
{
    const char *msg = (inmsg == NULL) ? "" : inmsg;
    DEBUG_CONSOLE_printf("MOC TIME - [%s]:%s\n",
                        getcurrtime(),
                        msg);
}

#   define  LOGDT(tag,fmt,arg) __android_log_print(ANDROID_LOG_DEBUG, tag, "[%s]:[%d]:" fmt, getcurrtime(), gettid(), arg)
#else
#   define  LOGDT(tag,fmt,arg) __android_log_print(ANDROID_LOG_DEBUG, tag, fmt, arg)
#endif /* __ENABLE_DEBUG_TIMESTAMPS__ */

#define LOG_TAG             "com.mocana.debug_console"
#define LOGD(fmt, args...)  LOGDT(LOG_TAG, fmt "\n", ##args)
#define VLOGD(fmt, va_args) __android_log_vprint(ANDROID_LOG_DEBUG, LOG_TAG, fmt, va_args)

#ifndef __DISABLE_BUFFERED_DEBUG_CONSOLE__
#undef CRLF
#define CRLF "\n"
static char logBuf[LOG_BUFSZ + 1] = { 0 };
static int logBufCount = 0;
#endif /* !__DISABLE_BUFFERED_DEBUG_CONSOLE__ */

#endif /* (!defined(__KERNEL__) && defined(__RTOS_ANDROID__)) */


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString(sbyte4 errorClass, sbyte *pPrintString)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    if (NULL != pPrintString)
    {
        DB_PRINT("%s", (char *)pPrintString);
    }
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printPointer(sbyte4 errorClass, void *ptr)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%p", ptr);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printInteger(sbyte4 errorClass, sbyte4 value)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%d", value);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printInteger2(sbyte4 errorClass, sbyte4 value1, sbyte4 value2)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%d%d", value1, value2);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printInteger3(sbyte4 errorClass, sbyte4 value1, sbyte4 value2, sbyte4 value3)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%d%d%d%s", value1, value2, value3, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printInteger4(sbyte4 errorClass, sbyte4 value1, sbyte4 value2, sbyte4 value3, sbyte4 value4)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%d%d%d%d%s", value1, value2, value3, value4, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printUnsignedInteger(sbyte4 errorClass, sbyte4 value)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%u", value);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printUnsignedInteger2(sbyte4 errorClass, sbyte4 value1, sbyte4 value2)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%u%u%s", value1, value2, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printUnsignedInteger3(sbyte4 errorClass, sbyte4 value1, sbyte4 value2, sbyte4 value3)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%u%u%u%s", value1, value2, value3, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printUnsignedInteger4(sbyte4 errorClass, sbyte4 value1, sbyte4 value2, sbyte4 value3, sbyte4 value4)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%u%u%u%u%s", value1, value2, value3, value4, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printNewLine(sbyte4 errorClass, sbyte *pPrintString)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    if (NULL != pPrintString)
    {
        DB_PRINT("%s", (char *)pPrintString);
    }
    DB_PRINT((char *)CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printUpTime(sbyte4 errorClass)
{
    ubyte4  upTime   = getUpTime();
    ubyte4  upTimeHi = upTime / 1000;
    ubyte4  upTimeLo = upTime % 1000;

    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT(" (%u.%u)", upTimeHi, upTimeLo);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printError(sbyte4 errorClass, sbyte *pPrintString, sbyte4 value)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%s%d%s", (pPrintString ? pPrintString : (sbyte *)""), value, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString3(sbyte4 errorClass, sbyte *pPrintString1, sbyte *pPrintString2, sbyte *pPrintString3)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%s%s%s%s",
             (pPrintString1 ? pPrintString1 : (sbyte *)""),
             (pPrintString2 ? pPrintString2 : (sbyte *)""),
             (pPrintString3 ? pPrintString3 : (sbyte *)""),
             CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_hexByte(sbyte4 errorClass, sbyte value)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%02x", ((int)value) & 0xff);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_hexInt(sbyte4 errorClass, sbyte4 value)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%08x", value);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printHexInt2(sbyte4 errorClass, sbyte4 value1, sbyte4 value2)
{

    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%08x%08x%s", value1, value2, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printHexInt3(sbyte4 errorClass, sbyte4 value1, sbyte4 value2, sbyte4 value3)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%08x%08x%08x%s", value1, value2, value3, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printHexInt4(sbyte4 errorClass, sbyte4 value1, sbyte4 value2, sbyte4 value3, sbyte4 value4)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%08x%08x%08x%08x%s", value1, value2, value3, value4, CRLF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printAsciiIPAddr(sbyte4 errorClass, sbyte4 value)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%03x.%03x.%03x.%03x", (value >> 24) & 0xFF,
                                    (value >> 16) & 0xFF,
                                    (value >> 8) & 0xFF,
                                    (value) & 0xFF);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString1AsciiIPAddr (sbyte4 errorClass, sbyte *pString1, sbyte4 ipValue)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DEBUG_CONSOLE_printString(errorClass, pString1);
    DEBUG_CONSOLE_printAsciiIPAddr(errorClass, ipValue);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString2(sbyte4 errorClass, sbyte *pPrintString1, sbyte *pPrintString2)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DEBUG_CONSOLE_printString(errorClass, pPrintString1);
    DEBUG_CONSOLE_printString(errorClass, pPrintString2);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString1Int1(sbyte4 errorClass, sbyte *pPrintString1, sbyte4 value1)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    if (NULL != pPrintString1)
    {
        DB_PRINT("%s", (char *)pPrintString1);
    }
    DB_PRINT("%d", value1);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString1HexInt1(sbyte4 errorClass, sbyte *pPrintString1, sbyte4 value1)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    if (NULL != pPrintString1)
    {
        DB_PRINT("%s", (char *)pPrintString1);
    }
    DB_PRINT("%08x", value1);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString2Int2(sbyte4 errorClass, sbyte *pPrintString1, sbyte4 value1, sbyte *pPrintString2, sbyte4 value2)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DEBUG_CONSOLE_printString1Int1(errorClass, pPrintString1, value1);
    DEBUG_CONSOLE_printString1Int1(errorClass, pPrintString2, value2);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printString2HexInt2(sbyte4 errorClass, sbyte *pPrintString1, sbyte4 value1, sbyte *pPrintString2, sbyte4 value2)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DEBUG_CONSOLE_printString1HexInt1(errorClass, pPrintString1, value1);
    DEBUG_CONSOLE_printString1HexInt1(errorClass, pPrintString2, value2);
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_printByte(sbyte4 errorClass, sbyte value)
{
    if ((m_errorClass & errorClass) != errorClass)
        return;

    DB_PRINT("%c", (int)value);
}


/*------------------------------------------------------------------*/

static ubyte
printChar(ubyte theChar)
{
    if ((32 > theChar) || (126 < theChar))
        return '.';

    return theChar;
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_hexDump(sbyte4 errorClass, ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4 index = 0;

    if ((m_errorClass & errorClass) != errorClass)
        return;

    while (index < mesgLen)
    {
        ubyte min = (16 > (mesgLen - index)) ? mesgLen - index : 16;
        ubyte  j, k;

        DB_PRINT("  %08x: ", index);

        for (j = 0; j < min; j++)
        {
            DB_PRINT("%02x ", (int) pMesg[index + j]);
        }

        for (k = j; k < 16; k++)
        {
            DB_PRINT("   ");
        }
        DB_PRINT("    ");

        for (k = 0; k < j; k++)
        {
            DB_PRINT("%c", (int) printChar(pMesg[index + k]));
        }
        DB_PRINT((char *)CRLF);

        index += 16;
    }
}


#ifndef __KERNEL__

/*------------------------------------------------------------------*/

#ifndef __MOCANA_DUMP_CONSOLE_TO_STDOUT__
static void
debugConsoleServer(void* tempListenPort)
{
    ubyte2      listenPort = (ubyte2)(unsigned long)tempListenPort;
    TCP_SOCKET  listenSocket;
    MSTATUS     status;

    if (OK > (status = TCP_LISTEN_SOCKET(&listenSocket, listenPort)))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("%s: Could not create listen socket\n", __FUNCTION__);
#endif
        goto nocleanup;
    }

    while (FALSE == mBreakServer)
    {
        mSocketConsole = (TCP_SOCKET)(-1);

        if (TRUE == mBreakServer)
            goto exit;

        if (OK > (status = TCP_ACCEPT_SOCKET(&mSocketConsole, listenSocket, &mBreakServer)))
            goto exit;

        if (TRUE == mBreakServer)
            goto exit;

        DEBUG_CONSOLE_printf("Mocana Debug Console Activated");
#ifdef __ENABLE_CUSTOM_DEBUG_CONSOLE_DEFS__
        DEBUG_CONSOLE_printf(" (__ENABLE_CUSTOM_DEBUG_CONSOLE_DEFS__ defined!)");
#else
        DEBUG_CONSOLE_printUpTime(0);
#endif
        DEBUG_CONSOLE_printf((char *)CRLF);

        while ((-1 != mSocketConsole) && (FALSE == mBreakServer))
            RTOS_sleepMS(1000);
    }

exit:
    TCP_CLOSE_SOCKET(listenSocket);

nocleanup:
#ifdef __ENABLE_ALL_DEBUGGING__
    printf("%s: Could not create listen socket (%d)\n", __FUNCTION__, status);
#endif

#ifdef __RTOS_FREERTOS__
    /* delete the task here in case of FREERTOS , as free rtos task completion means need to kill task
        In case TCP stack is working this task will not be closed.*/
    vTaskDelete( NULL );
#endif

    return;
}
#endif


/*------------------------------------------------------------------*/

extern sbyte4
DEBUG_CONSOLE_start(ubyte2 listenPort)
{
    MSTATUS     status;

#ifndef __MOCANA_DUMP_CONSOLE_TO_STDOUT__
    RTOS_THREAD tid;

    mBreakServer   = FALSE;
    if (OK > (status = RTOS_createThread(debugConsoleServer, (void *)(unsigned long)listenPort, DEBUG_CONSOLE, &tid)))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        printf("%s: Console debug thread spawn failed (%d).\n", __FUNCTION__, status);
#endif
    }
#else
    MOC_UNUSED(listenPort);
#ifdef __ENABLE_ALL_DEBUGGING__
    DB_PRINT("%s: Should not spawn debug thread\n", __FUNCTION__);
#endif
    status = ERR_DEBUG_CONSOLE;
#endif

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_init(void)
{
#ifndef __MOCANA_DUMP_CONSOLE_TO_STDOUT__
    mBreakServer   = FALSE;
    mSocketConsole = (TCP_SOCKET)(-1);
#endif
#if !defined(__ENABLE_MOCANA_SPLIT_DRIVER__)
    (void) RTOS_deltaMS(NULL, &gDbgStartTime);
#endif
    return;
}


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_stop(void)
{
#ifndef __MOCANA_DUMP_CONSOLE_TO_STDOUT__
    mBreakServer   = TRUE;
    mSocketConsole = (TCP_SOCKET)(-1);
#endif
    return;
}


/*------------------------------------------------------------------*/

#if defined(__MOCANA_DUMP_CONSOLE_TO_STDOUT__) && \
    !defined(__DISABLE_MOCANA_FILE_SYSTEM_HELPER__) /* jic FILE * not supported */
static FILE *dboutput = NULL;

extern sbyte4
DEBUG_CONSOLE_setOutput(char *filename)
{
#if !defined(__RTOS_ANDROID__) && !defined(__UCOS_DIRECT_RTOS__)
    FILE   *fod;
    MSTATUS status  = OK;

    DB_PRINT("Switching output stream\n");
    if (dboutput)
    {
        (void) fclose(dboutput);
        dboutput = NULL;
    }
#if defined(__ENABLE_DIGICERT_POSIX_SUPPORT__)
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        fod = fdopen(fd, "w");
        if (NULL == fod)
        {
            close(fd);
        }
    }
    else
    {
        fod = NULL;
    }
#else
    fod = fopen(filename, "w");
#endif
    if (NULL == fod)
    {
        ERROR_PRINT(("Failed to open %s for writing", filename));
        status = ERR_DEBUG_CONSOLE_CHANNEL;
        goto exit;
    }
    dboutput = fod;

exit:
#else
    MSTATUS status = ERR_DEBUG_CONSOLE;
#endif
    return (sbyte4)status;
}

#else
extern sbyte4 DEBUG_CONSOLE_setOutput(char *filename) { return (sbyte4)ERR_DEBUG_CONSOLE; }
#endif

/*------------------------------------------------------------------*/

extern void DEBUG_CONSOLE_setPrintClass(sbyte4 m_class)
{
    m_errorClass |= m_class;
}

/*------------------------------------------------------------------*/

extern void DEBUG_CONSOLE_unsetPrintClass(sbyte4 m_class)
{
    m_errorClass &= ~m_class;
}

/*------------------------------------------------------------------*/

#else /* __KERNEL__ */
extern void   DEBUG_CONSOLE_init(void) { return; }
extern sbyte4 DEBUG_CONSOLE_start(ubyte2 listenPort) { return (sbyte4)ERR_DEBUG_CONSOLE; }
extern void   DEBUG_CONSOLE_stop(void) { return; }
extern sbyte4 DEBUG_CONSOLE_setOutput(char *filename) { return (sbyte4)ERR_DEBUG_CONSOLE; }
extern void DEBUG_CONSOLE_setPrintClass(sbyte4 m_class) { return; }
extern void DEBUG_CONSOLE_unsetPrintClass(sbyte4 m_class) { return; }
#endif


/*------------------------------------------------------------------*/

extern void
DEBUG_CONSOLE_dump_data(ubyte *address, int size, int limit, int wsize,
                        char *title)
{
    ubyte4      i, repeat, wperline;
    int         psize;
    ubyte       *paddress = address;
    static char linebuf[120], ascbuf[40];
    char        *lp, *ap;

    if (0 >= size)
        return;

    if (0 >= limit)
        limit = size;

    if (title)
    {
        DB_PRINT("===== Dump: %s [%d]\n", title, size);
    }
    size     = (size + 3) & 0xfffc;
    psize    = (size > (limit+16)) ? limit : size;
    repeat   = psize/wsize;
    wperline = 16/wsize;
    lp       = linebuf;
    ap       = ascbuf;
    *lp      = 0;
    *ap      = 0;
    for (i = 0; i < repeat; i++)
    {
        if ((i % wperline) == 0)
        {
            *lp = 0;
            *ap = 0;
            DB_PRINT("%s | %s\n", linebuf, ascbuf);
            lp  = linebuf;
            (void) sprintf(lp, "%08lX: ", (unsigned long)(uintptr)paddress);
            lp += 10;
            ap  = ascbuf;
            *ap = 0;
        }
        if (1 == wsize)
        {
            (void) sprintf(lp, "%02X ", *paddress);
            lp += 3;
            *ap++ = isprint(*paddress) ? *paddress : '.';
        }
        else if (2 == wsize)
        {
            (void) sprintf(lp, "%04X ", *(ubyte2 *)paddress);
            lp += 5;
        }
        else
        {
            (void) sprintf(lp, "%08X ", (unsigned int)(*(ubyte4 *)paddress));
            lp += 9;
        }
        paddress += wsize;
    }
    *lp++ = '\n'; *lp = 0;
    DB_PRINT(linebuf, 0);

    /* Block too big.  Just dump the tail end */
    if (size > psize)
    {
        DB_PRINT("...\n");
        DEBUG_CONSOLE_dump_data(&address[size-16], 16, 16, wsize, NULL);
    }
}

#ifdef __ENABLE_MOCANA_DEBUG_FORWARD__
static DEBUG_FORWARD_callback dbForwardCallback = NULL;

MOC_EXTERN void DEBUG_FORWARD_set(DEBUG_FORWARD_callback forwardCallback)
{
    if (NULL != forwardCallback)
    {
        dbForwardCallback = forwardCallback;
    }
}
#endif /* __ENABLE_MOCANA_DEBUG_FORWARD__ */

/*------------------------------------------------------------------*/

#if !defined(__MOCANA_DUMP_CONSOLE_TO_STDOUT__)
extern void
DEBUG_CONSOLE_printf(const char *format, ...)
{
#ifndef __KERNEL__
    moc_va_list valist;
    MOC_VA_START(valist, format);

    if ((TCP_SOCKET)(-1) != mSocketConsole)
    {
        sbyte4 numBytesWritten;
        sbyte printString[LOG_BUFSZ + 1] = { 0 };
#ifdef __ENABLE_MOCANA_PRINTF__
        sbyte4 stringLength = MOC_VSNPRINTF(printString, LOG_BUFSZ, (const ubyte *)format, &valist);
#else
        int stringLength = vsnprintf((char *)printString, LOG_BUFSZ, format, valist);
#endif
        if ((0 < stringLength) &&
            (OK > TCP_WRITE(mSocketConsole, printString, (ubyte4)stringLength,
                            &numBytesWritten)))
        {
            mSocketConsole = (TCP_SOCKET)(-1);
        }
    }

    MOC_VA_END(valist);
#endif
    return;
}

#elif defined(__KERNEL__)
extern void
DEBUG_CONSOLE_printf(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintk(format, ap);
    va_end(ap);
}

#elif defined(__RTOS_ANDROID__)
static char *
expand_string(const char *format, va_list ap)
{
    char buf[LOG_BUFSZ + 1];

    int total = vsnprintf(buf, LOG_BUFSZ, format, ap);
    char *log = NULL;
    log = (char *) malloc(sizeof(char) * (total + 1));
    if (log)
    {
        vsnprintf(log, total, format, ap);
        log[total] = 0;
    }
    return log;
}

#ifdef __DISABLE_BUFFERED_DEBUG_CONSOLE__
extern void
DEBUG_CONSOLE_printf(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    VLOGD(format, ap);
    va_end(ap);
}

#else  /* __DISABLE_BUFFERED_DEBUG_CONSOLE__  */

extern void
DEBUG_CONSOLE_printf(const char *format, ...)
{
    int count = logBufCount; /* !!! jic multi-threaded */;
    char *eol;

    va_list ap;
    va_start(ap, format);

    if ((0 == count) && /* find last NL */
        (NULL != (eol = strrchr(format, '\n'))) && ('\0' == *(eol + 1)))
    {
        char *expanded = expand_string(format, ap);
        LOGD("%s", expanded);
        if (expanded)
        {
            free(expanded);
        }
    }
    else
    {
        count += vsnprintf(logBuf + count, LOG_BUFSZ - count, format, ap);
        logBuf[count] = '\0'; /* jic */

        if (NULL == (eol = strrchr(logBuf, '\n')))
        {
            if (LOG_BUFSZ <= count)
            {
                logBuf[LOG_BUFSZ] = '\0'; /* jic */
                LOGD("%s", (char*)logBuf);
                logBufCount = 0;
            }
            else logBufCount = count;
        }
        else
        {
            char *k;
            *eol++ = '\0';
            if (NULL != (k = strstr(logBuf, "bytes): ")))
            {
                k[7] = '\0'; /* don't print keying materials and keys */
            }
#if 0
            else if (NULL != (k = strstr(logBuf, "socket on ")))
                k[9] = '\0';
            else if (NULL != (k = strstr(logBuf, "dest=")))
                k[4] = '\0';
            else if (NULL != (k = strstr(logBuf, "laddr ")))
                k[5] = '\0';
            else if (NULL != (k = strstr(logBuf, "TSi: ")))
                k[4] = '\0';
            else if (NULL != (k = strstr(logBuf, "ESP ")))
                k[3] = '\0';
            else if (NULL != (k = strstr(logBuf, "add_ip_interface:")))
                k[16] = '\0';
            else if (NULL != (k = strstr(logBuf, "IPV4_ADDRESS(")))
                k[12] = '\0';
#endif
            LOGD("%s", (char*)logBuf);
            count -= (eol - logBuf);
            if (0 < count)
            {
                memmove(logBuf, eol, count);
                logBuf[count] = '\0';
                logBufCount = count;
            }
            else logBufCount = 0; /* jic */
        }
    }

    va_end(ap);

    return;
} /* ANDROID_VPN_DEBUG_printf */

#endif /* __DISABLE_BUFFERED_DEBUG_CONSOLE__  */

extern void
DEBUG_CONSOLE_TAG_printf(const char *tag, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);

    char *expanded = expand_string(format, ap);
    LOGDT(tag, "%s", expanded);

    va_end(ap);

    if (expanded)
    {
        free(expanded);
    }

    return;
}

#elif defined(__UCOS_DIRECT_RTOS__)
extern void
DEBUG_CONSOLE_printf(const char *format, ...)
{
    char str[81];
    va_list ap;

    va_start(ap, format);
    vnsprintf(str, sizeof(str), format, ap);
    va_end(ap);

    /* Pass the formatted string to Net_Secure instead of
    directly outputting it here */
    SSL_TRACE_DBG( (str) );
}
#elif defined(__QNX_RTOS_SLOG__)
#include <sys/slog.h>
#include <sys/slogcodes.h>

extern void
DEBUG_CONSOLE_printf(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vslogf(_SLOG_SETCODE(_SLOGC_TEST, 10), _SLOG_ERROR, format, ap);
    va_end(ap);

}
#else

extern void DEBUG_CONSOLE_printfVarList(const char *format, moc_va_list valist)
{
#ifdef __ENABLE_MOCANA_PRINTF__
    sbyte printString[LOG_BUFSZ + 1] = { 0 };
#endif
#ifdef __ENABLE_MOCANA_DEBUG_FORWARD__
    sbyte dbgFwdMsgString[LOG_BUFSZ + 1] = { 0 };
#endif

#ifdef __ENABLE_MOCANA_PRINTF__
    MOC_VSNPRINTF(printString, LOG_BUFSZ, (const ubyte *)format, &valist);
#endif

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__
    if (dboutput)
    {
#ifdef __ENABLE_MOCANA_PRINTF__
        fprintf(dboutput, (char *)printString);
#else
        (void) vfprintf(dboutput, format, valist);
#endif
        (void) fflush(dboutput);
    }
    else
#endif /* __DISABLE_MOCANA_FILE_SYSTEM_HELPER__ */
    {
#ifdef __ENABLE_MOCANA_PRINTF__
        printf((char *)printString);
#else
        (void) vprintf(format, valist);
#endif
    }

#ifdef __ENABLE_MOCANA_DEBUG_FORWARD__
    if (NULL != dbForwardCallback)
    {
        vsprintf_s(dbgFwdMsgString, LOG_BUFSZ, (const char *)format, valist);
        dbForwardCallback(dbgFwdMsgString);
    }
#endif

    MOC_VA_END(valist);
#ifdef __RTOS_THREADX__
    tx_thread_relinquish();
#endif
}

extern void
DEBUG_CONSOLE_printf(const char *format, ...)
{
    moc_va_list valist;
#ifdef __ENABLE_MOCANA_PRINTF__
    sbyte printString[LOG_BUFSZ + 1] = { 0 };
#endif
#ifdef __ENABLE_MOCANA_DEBUG_FORWARD__
    sbyte dbgFwdMsgString[LOG_BUFSZ + 1] = { 0 };
#endif
    MOC_VA_START(valist, format);

    DEBUG_CONSOLE_printfVarList(format, valist);

    MOC_VA_END(valist);
}
#endif

#endif /* __ENABLE_MOCANA_DEBUG_CONSOLE__ */

