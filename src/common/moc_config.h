/*
 * moc_config.h
 *
 * Update Message - Smart Device Manager
 *
 * Config File support for the Update Client
 *
 * Copyright Mocana Corp 2012. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

/*! \file moc_config.h Mocana Configuration File Parser
This header file contains definitions, enumerations, and function declarations
for a generic Config File Parser used by various Mocana products and
applications.

\since 6.0
\version 6.0 and later

! Flags
There are no flag dependencies to use this header file.

*/

#ifndef __MOC_CONFIG_HEADER__
#define __MOC_CONFIG_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

typedef MSTATUS (*CONFIG_Callback)(ubyte* pLineStart, ubyte4 bytesLeft,
				   void* arg, ubyte4 *bytesUsed);


typedef struct {
  const sbyte *       key;
  CONFIG_Callback     callback;
  void*               callback_arg;
} CONFIG_ConfigItem;


MOC_EXTERN MSTATUS CONFIG_parseData(ubyte* data, ubyte4 dataLen, CONFIG_ConfigItem* configs);

MOC_EXTERN MSTATUS CONFIG_gotoValue(ubyte* line, ubyte4 dataLeft, const sbyte* fieldName, 
			 sbyte delimChar, ubyte4* bytesUsed);
MOC_EXTERN MSTATUS CONFIG_gotoSection(ubyte* line, ubyte4 dataLeft, const sbyte* fieldName, 
			 ubyte4* bytesUsed);
MOC_EXTERN ubyte4 CONFIG_skipSpace(ubyte* ptr, ubyte4 dataLeft);
MOC_EXTERN ubyte4 CONFIG_nextLine(ubyte* ptr, ubyte4 dataLeft);
MOC_EXTERN MSTATUS CONFIG_getValue(sbyte* line, ubyte4 bytesLeft, const sbyte* fieldName,
        sbyte delimChar, sbyte** value,  ubyte4* valueOffset, ubyte4* valueLen);
MOC_EXTERN MSTATUS CONFIG_readToEOL(sbyte* text, ubyte4 bytesLeft, ubyte4* length);

  /* Some CONFIG_Callback helper functions */

  /** The void* parameter requires an sbyte** callback argument */
MOC_EXTERN MSTATUS CONFIG_copyString(ubyte*, ubyte4, void*, ubyte4 *);

  /** The void* parameter requires a ubyte4* callback argument */
MOC_EXTERN MSTATUS CONFIG_copyUByte4(ubyte*, ubyte4, void*, ubyte4 *);

#ifdef __cplusplus
}
#endif


#endif  /*#ifndef __MOC_CONFIG_HEADER__ */
