/* msg_logger.h
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
#ifndef __MSG_LOGGER_HEADER__
#define __MSG_LOGGER_HEADER__

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/

/* Message Log Levels */
typedef enum MsgLogLevel
{
    MSG_LOG_VERBOSE     = 0,
    MSG_LOG_INFO        = 1,
    MSG_LOG_DEBUG       = 2,
    MSG_LOG_WARNING     = 3,
    MSG_LOG_ERROR       = 4,
    MSG_LOG_NONE        = 5
} MsgLogLevel;

/*----------------------------------------------------------------------------*/

#if defined(__RTOS_ZEPHYR__)

#define MSG_LOG_printEx(_level, _pLabel, _pFormat, ...) \
    MSG_LOG_printf(_level, _pFormat, __VA_ARGS__)

#define MSG_LOG_print(_level, _pFormat, ...) \
    MSG_LOG_printf(_level, _pFormat, __VA_ARGS__)

#define MSG_LOG_printRaw(_level, _pFormat, ...) \
    MSG_LOG_printf(_level, _pFormat, __VA_ARGS__)

#define MSG_LOG_printRawBuffer(_level, _pBuffer, _bufferLen) \
    MSG_LOG_printHexBufferEx(_level, _pBuffer, _bufferLen)

#else

#define MSG_LOG_printEx(_level, _pLabel, _pFormat, ...) \
    do { if (MSG_LOG_shouldPrint(_level)) { MSG_LOG_printStartEx(_level, _pLabel); DEBUG_CONSOLE_printf(_pFormat, __VA_ARGS__); MSG_LOG_printEnd(); } } while (0)

#define MSG_LOG_print(_level, _pFormat, ...) \
    do { if (MSG_LOG_shouldPrint(_level)) { MSG_LOG_printStart(_level); DEBUG_CONSOLE_printf(_pFormat, __VA_ARGS__); MSG_LOG_printEnd(); } } while (0)

#define MSG_LOG_printRaw(_level, _pFormat, ...) \
    do { if (MSG_LOG_shouldPrint(_level)) { MSG_LOG_printStartRaw(); DEBUG_CONSOLE_printf(_pFormat, __VA_ARGS__); MSG_LOG_printEnd(); } } while (0)

#define MSG_LOG_printRawBuffer(_level, _pBuffer, _bufferLen) \
    do { if (MSG_LOG_shouldPrint(_level)) { MSG_LOG_printStartRaw(); MSG_LOG_printHexBuffer(_pBuffer, _bufferLen); MSG_LOG_printEnd(); } } while (0)

#endif

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MSG_LOG_init(MsgLogLevel level);

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_uninit(void);

/*----------------------------------------------------------------------------*/

MOC_EXTERN intBoolean MSG_LOG_isLogLevelSet(void);

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MSG_LOG_changeLevel(MsgLogLevel level);

/*----------------------------------------------------------------------------*/

MOC_EXTERN MsgLogLevel MSG_LOG_getLevel(void);

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MSG_LOG_convertStringLevel(sbyte *pLevelStr, MsgLogLevel *pLevel);

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_setLabel(sbyte *pLabel);

/*----------------------------------------------------------------------------*/

MOC_EXTERN byteBoolean MSG_LOG_shouldPrint(MsgLogLevel level);

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_printStartEx(MsgLogLevel level, sbyte *pLabel);

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_printStart(MsgLogLevel level);

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_printStartRaw();

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_printEnd(void);

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_printHexBuffer(ubyte *pBuffer, ubyte4 bufferLen);

/*----------------------------------------------------------------------------*/

#ifdef __RTOS_ZEPHYR__
MOC_EXTERN void MSG_LOG_printHexBufferEx(MsgLogLevel level, ubyte *pBuffer, ubyte4 bufferLen);

/*----------------------------------------------------------------------------*/

MOC_EXTERN void MSG_LOG_printf(MsgLogLevel level, sbyte *pFormat, ...);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __MSG_LOGGER_HEADER__ */