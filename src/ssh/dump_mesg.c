/*
 * dump_mesg.c
 *
 * Dump Message
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__))
#ifdef __ENABLE_ALL_DEBUGGING__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../ssh/ssh.h" /* MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE */

/*------------------------------------------------------------------*/

static ubyte *
sshMessageType(ubyte mesgType, ubyte4 authMethod)
{
    switch (mesgType)
    {
        case   1: return (ubyte *)"SSH_MSG_DISCONNECT";
        case   2: return (ubyte *)"SSH_MSG_IGNORE";
        case   3: return (ubyte *)"SSH_MSG_UNIMPLEMENTED";
        case   4: return (ubyte *)"SSH_MSG_DEBUG";
        case   5: return (ubyte *)"SSH_MSG_SERVICE_REQUEST";
        case   6: return (ubyte *)"SSH_MSG_SERVICE_ACCEPT";
        case   7: return (ubyte *)"SSH_MSG_EXT_INFO";

        case  20: return (ubyte *)"SSH_MSG_KEXINIT";
        case  21: return (ubyte *)"SSH_MSG_NEWKEYS";

        case  30: return (ubyte *)"SSH_MSG_KEXDH_INIT";
        case  31: return (ubyte *)"SSH_MSG_KEXDH_REPLY";
        case  32: return (ubyte *)"SSH_MSG_KEX_DH_GEX_INIT";
        case  33: return (ubyte *)"SSH_MSG_KEX_DH_GEX_REPLY";
        case  34: return (ubyte *)"SSH_MSG_KEY_DH_GEX_REQUEST";

        case  50: return (ubyte *)"SSH_MSG_USERAUTH_REQUEST";
        case  51: return (ubyte *)"SSH_MSG_USERAUTH_FAILURE";
        case  52: return (ubyte *)"SSH2_MSG_USERAUTH_SUCCESS";
        case  53: return (ubyte *)"SSH_MSG_USERAUTH_BANNER";

        case  60:
           if(authMethod == MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE)
           {
               return (ubyte *)"SSH_MSG_USERAUTH_INFO_REQUEST";
           }
           else
           {
               return (ubyte *)"SSH_MSG_USERAUTH_PK_OK";
           }

        case  61: return (ubyte *)"SSH_MSG_USERAUTH_INFO_RESPONSE";

        case  80: return (ubyte *)"SSH_MSG_GLOBAL_REQUEST";
        case  81: return (ubyte *)"SSH_MSG_REQUEST_SUCCESS";
        case  82: return (ubyte *)"SSH_MSG_REQUEST_FAILURE";

        case  90: return (ubyte *)"SSH_MSG_CHANNEL_OPEN";
        case  91: return (ubyte *)"SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
        case  92: return (ubyte *)"SSH_MSG_CHANNEL_OPEN_FAILURE";
        case  93: return (ubyte *)"SSH_MSG_CHANNEL_WINDOW_ADJUST";
        case  94: return (ubyte *)"SSH_MSG_CHANNEL_DATA";
        case  95: return (ubyte *)"SSH_MSG_CHANNEL_EXTENDED_DATA";
        case  96: return (ubyte *)"SSH_MSG_CHANNEL_EOF";
        case  97: return (ubyte *)"SSH_MSG_CHANNEL_CLOSE";
        case  98: return (ubyte *)"SSH_MSG_CHANNEL_REQUEST";
        case  99: return (ubyte *)"SSH_MSG_CHANNEL_SUCCESS";
        case 100: return (ubyte *)"SSH_MSG_CHANNEL_FAILURE";

        default: break;
    }

    return (ubyte *)"UNKNOWN";
}


/*------------------------------------------------------------------*/

static ubyte *
sftpMessageType(ubyte mesgType)
{
    switch (mesgType)
    {
        case   1: return (ubyte *)"SSH_FXP_INIT";
        case   2: return (ubyte *)"SSH_FXP_VERSION";

        case   3: return (ubyte *)"SSH_FXP_OPEN";
        case   4: return (ubyte *)"SSH_FXP_CLOSE";
        case   5: return (ubyte *)"SSH_FXP_READ";
        case   6: return (ubyte *)"SSH_FXP_WRITE";
        case   7: return (ubyte *)"SSH_FXP_LSTAT";
        case   8: return (ubyte *)"SSH_FXP_FSTAT";
        case   9: return (ubyte *)"SSH_FXP_SETSTAT";
        case  10: return (ubyte *)"SSH_FXP_FSETSTAT";
        case  11: return (ubyte *)"SSH_FXP_OPENDIR";
        case  12: return (ubyte *)"SSH_FXP_READDIR";
        case  13: return (ubyte *)"SSH_FXP_REMOVE";
        case  14: return (ubyte *)"SSH_FXP_MKDIR";
        case  15: return (ubyte *)"SSH_FXP_RMDIR";
        case  16: return (ubyte *)"SSH_FXP_REALPATH";
        case  17: return (ubyte *)"SSH_FXP_STAT";
        case  18: return (ubyte *)"SSH_FXP_RENAME";
        case  19: return (ubyte *)"SSH_FXP_READLINK";
        case  20: return (ubyte *)"SSH_FXP_SYMLINK";

        case 101: return (ubyte *)"SSH_FXP_STATUS";
        case 102: return (ubyte *)"SSH_FXP_HANDLE";
        case 103: return (ubyte *)"SSH_FXP_DATA";
        case 104: return (ubyte *)"SSH_FXP_NAME";
        case 105: return (ubyte *)"SSH_FXP_ATTRS";

        case 200: return (ubyte *)"SSH_FXP_EXTENDED";
        case 201: return (ubyte *)"SSH_FXP_EXTENDED_REPLY";

        default: break;
    }

    return (ubyte *)"UNKNOWN";
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

static void
printHexAsciiDump(ubyte *pMesg, ubyte4 mesgLen)
{
    ubyte4 index = 1;  /* Start from index 1 to skip the message type byte */

    while (index < mesgLen)
    {
        ubyte min = (16 > (mesgLen - index)) ? mesgLen - index : 16;
        ubyte  j, k;

        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "  ");
        DEBUG_HEXINT(DEBUG_SSH_MESSAGES, index-1);
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, ": ");

        for (j = 0; j < min; j++)
        {
            DEBUG_HEXBYTE(DEBUG_SSH_MESSAGES, (sbyte)(pMesg[index + j]));
            DEBUG_PRINT(DEBUG_SSH_MESSAGES, " ");
        }

        for (k = j; k < 16; k++)
            DEBUG_PRINT(DEBUG_SSH_MESSAGES, "   ");

        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "    ");

        for (k = 0; k < j; k++)
             DEBUG_PRINTBYTE(DEBUG_SSH_MESSAGES, printChar(pMesg[index + k]));

        DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *)(""));

        index += 16;
    }
}

/*------------------------------------------------------------------*/

extern void
DUMP_MESG_sshMessage(ubyte *pMesg, ubyte4 mesgLen, intBoolean isOutBound, ubyte4 authMethod)
{
    if (TRUE == isOutBound)
    {
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "Time(ms) = ");
        DEBUG_UPTIME(DEBUG_SSH_MESSAGES);
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, ", Outbound message of type ");
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, (sbyte *)(sshMessageType(*pMesg, authMethod)));
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "(");
        DEBUG_INT(DEBUG_SSH_MESSAGES, *pMesg);
        DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *)("):"));
    }
    else
    {
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "Time(ms) = ");
        DEBUG_UPTIME(DEBUG_SSH_MESSAGES);
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, ",  Inbound message of type ");
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, (sbyte *)(sshMessageType(*pMesg, authMethod)));
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "(");
        DEBUG_INT(DEBUG_SSH_MESSAGES, *pMesg);
        DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *)("):"));
    }

#ifdef __ENABLE_DIGICERT_SSH_CHANNEL_ID_DEBUG__
    if ( (4 < mesgLen) &&
        ((81 == *pMesg) || (82 == *pMesg) || (91 == *pMesg) || (92 == *pMesg) ||
         (94 == *pMesg) || (95 == *pMesg) || (96 == *pMesg) || (97 == *pMesg)) )
    {
        ubyte4 channelId;

        channelId   = pMesg[1];
        channelId <<= 8;
        channelId  |= pMesg[2];
        channelId <<= 8;
        channelId  |= pMesg[3];
        channelId <<= 8;
        channelId  |= pMesg[4];

        DEBUG_PRINT(DEBUG_SSH_MESSAGES, ">>>> Channel Id = ");
        DEBUG_HEXINT(DEBUG_SSH_MESSAGES, channelId);
        DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, " <<<<");
    }
#endif /* __ENABLE_DIGICERT_SSH_CHANNEL_ID_DEBUG__ */

    printHexAsciiDump(pMesg, mesgLen);
}


/*------------------------------------------------------------------*/

extern void
DUMP_MESG_sftpMessage(ubyte *pMesg, ubyte4 mesgLen, intBoolean isOutBound)
{
    if (TRUE == isOutBound)
    {
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "SFTP/SESSION: Time(ms) = ");
        DEBUG_UPTIME(DEBUG_SSH_MESSAGES);
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, ", Outbound message of type ");
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, (sbyte *)(sftpMessageType(*pMesg)));
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "(");
        DEBUG_INT(DEBUG_SSH_MESSAGES, *pMesg);
        DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *)("):"));
    }
    else
    {
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "SFTP/SESSION: Time(ms) = ");
        DEBUG_UPTIME(DEBUG_SSH_MESSAGES);
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, ",  Inbound message of type ");
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, (sbyte *)(sftpMessageType(*pMesg)));
        DEBUG_PRINT(DEBUG_SSH_MESSAGES, "(");
        DEBUG_INT(DEBUG_SSH_MESSAGES, *pMesg);
        DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *)("):"));
    }

    printHexAsciiDump(pMesg, mesgLen);

    DEBUG_PRINTNL(DEBUG_SSH_MESSAGES, (sbyte *)(""));
}

#endif /* __ENABLE_ALL_DEBUGGING__ */
#endif /* (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__)) */

