/*
 * mprintf.c
 *
 * Mocana printf
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

#ifdef __ENABLE_DIGICERT_PRINTF__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_MPRINTF_FLOAT__
#include "../common/vlong.h"
#endif
#include "../common/moc_segment.h"

#include <stdarg.h>

#include "../common/mprintf.h"


#define MAX_PRECISION_VALUE     (4096)
#define MAX_WIDTH_VALUE         (4096)


#define FLAG_PLUS_SIGN          (0x01)
#define FLAG_LEFT_ALIGN         (0x02)
#define FLAG_SPACE              (0x04)
#define FLAG_PAD_ZERO           (0x08)
#define FLAG_ALT_FORM           (0x10)


/* length modifier */
enum lenModifier
{
    LMOD_NONE       = 0,
    LMOD_HH         = 1,
    LMOD_H          = 2,
    LMOD_L          = 3,
    LMOD_LL         = 4,
    LMOD_J          = 5,
    LMOD_Z          = 6,
    LMOD_T          = 7,
    LMOD_BL         = 8
};

enum mprtfParseState
{
    ST_INVALID      = 0,
    ST_CHAR         = 1,
    ST_FLAG         = 2,
    ST_WIDTH        = 3,
    ST_PRECISION    = 4,
    ST_LENGTH       = 5,
    ST_SPECIFIER    = 6,
    ST_DONE         = 7
};


/* data type macro */
#define DT_VOID            void
#define DT_S_CHAR          signed char
#define DT_U_CHAR          unsigned char
#define DT_S_SHORT         signed short
#define DT_U_SHORT         unsigned short
#define DT_S_INT           signed int
#define DT_U_INT           unsigned int
#define DT_S_LONG          signed long
#define DT_U_LONG          unsigned long
#define DT_PTR             uintptr

#ifdef __ENABLE_MPRINTF_LONG_LONG__
#define DT_S_LONG_LONG     signed long long
#define DT_U_LONG_LONG     unsigned long long
#endif

#ifdef __ENABLE_MPRINTF_FLOAT__
#define DT_FLOAT           float
#define DT_DOUBLE          double
#define DT_LONG_DOUBLE     long double


#define DBL_PREC            (52)
#define DBL_BIAS            (1023)
#define DBL_EMAX            (2047)          /* 2^11 -1 */
#define MASK_EXP            (0x7FF00000L)
#define MASK_SIGN           (0x80000000L)
#define MASK_MANT           (0x000FFFFFL)
#define MASK_HIDDEN_BIT     (0x00100000L)

#define GET_EXPONENT(X)     ((X & MASK_EXP) >> 20)
#define GET_SIGN(X)         ((X & MASK_SIGN) ? 1 : 0)

typedef union uNum
{
    DT_DOUBLE   f;
    ubyte4      dword[2];
}uNum;
#endif /* __ENABLE_MPRINTF_FLOAT__ */


#define GET_VA_LIST(X)                ((X)->pVaList->ap)

#define MPRINTF_CONV_FLAG(X)          (X)->convFlag
#define MPRINTF_CONV_WIDTH(X)         (X)->convWidth
#define MPRINTF_CONV_PRECISION(X)     (X)->convPrecision
#define MPRINTF_CONV_LENMOD(X)        (X)->convLenMod
#define MPRINTF_CONV_SPEC(X)          (X)->convSpecifier


#define IS_FLAG_PLUS_SIGN(X)          ((X)->convFlag & FLAG_PLUS_SIGN)
#define IS_FLAG_LEFT_ALIGN(X)         ((X)->convFlag & FLAG_LEFT_ALIGN)
#define IS_FLAG_SPACE(X)              ((X)->convFlag & FLAG_SPACE)
#define IS_FLAG_PAD_ZERO(X)           ((X)->convFlag & FLAG_PAD_ZERO)
#define IS_FLAG_ALT_FORM(X)           ((X)->convFlag & FLAG_ALT_FORM)

#define SET_FLAG(X,Y)                 ((X)->convFlag = (X)->convFlag | Y)
#define SET_LENMOD(X,Y)               ((X)->convLenMod = Y)

#define CONV_BUFLEN                   (64)

typedef struct MprtfState
{
    ubyte4      state;

    moc_va_list* pVaList;

    /* conversion variables */
    ubyte4      convFlag;
    sbyte4      convWidth;
    sbyte4      convPrecision;
    ubyte4      convLenMod;
    ubyte       convSpecifier;

    /* buffer for storing temporary conversion results */
    ubyte       convBuf[CONV_BUFLEN];

#ifdef __ENABLE_MPRINTF_FLOAT__
    /* for double type */
    sbyte4      exponent;
    sbyte4      sign;
#endif

    /* output buffer */
    mocSegDescr* pHeadOfSegs;
    mocSegDescr* pCurrentSeg;

    ubyte4      numBytesWritten;

} MprtfState;

typedef struct Integer
{
    ubyte4      numBytes;

    union
    {
        DT_S_LONG           sLong;
        DT_U_LONG           uLong;

#ifdef __ENABLE_MPRINTF_LONG_LONG__
        DT_S_LONG_LONG      sLonglong;
        DT_U_LONG_LONG      uLonglong;
#endif
    } value;
} Integer;


/*------------------------------------------------------------------*/

static MSTATUS
resetConversionInfo(MprtfState *pPrtfState)
{
    MSTATUS status = OK;

    MPRINTF_CONV_FLAG(pPrtfState)         = 0;
    MPRINTF_CONV_WIDTH(pPrtfState)        = -1;
    MPRINTF_CONV_PRECISION(pPrtfState)    = -1;
    MPRINTF_CONV_LENMOD(pPrtfState)       = 0;
    MPRINTF_CONV_SPEC(pPrtfState)         = 0;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
clearBuffer(MprtfState *pPrtfState)
{
    MSTATUS         status = OK;
    mocSegDescr*    pCurSeg = pPrtfState->pHeadOfSegs;

    while (NULL != pCurSeg)
    {
        DIGI_MEMSET(GET_SEG_BUFFER(pCurSeg), 0x00, GET_SEG_BUFFER_LEN(pCurSeg));
        pCurSeg = GET_NEXT_SEG(pCurSeg);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
copyBufToOutput(const ubyte *pBuf, ubyte4 size, MprtfState *pPrtfState)
{
    MSTATUS         status = OK;
    mocSegDescr*    pCurSeg = pPrtfState->pCurrentSeg;

    if (NULL == pCurSeg)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    while (0 < size)
    {
        if ((NULL != GET_SEG_BUFFER(pCurSeg)) &&
            (GET_SEG_BYTES_USED(pCurSeg) < GET_SEG_BUFFER_LEN(pCurSeg)))
        {
            *(GET_SEG_BUFFER(pCurSeg) + GET_SEG_BYTES_USED(pCurSeg)) = *pBuf++;

            GET_SEG_BYTES_USED(pCurSeg)++;
            pPrtfState->numBytesWritten++;
            size--;
        }
        else if (NULL == (pCurSeg = GET_NEXT_SEG(pCurSeg)))
        {
            break;
        }
    }

    if (0 < size)
    {
        clearBuffer(pPrtfState);

        status = ERR_MPRINTF_BUFFER_FULL;
        goto exit;
    }

    pPrtfState->pCurrentSeg = pCurSeg;
    pCurSeg = NULL;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_COMMON, "MPRINTF:copyBufToOutput() returns status = ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
addPadding(ubyte ch, sbyte4 size, MprtfState *pPrtfState)
{
    MSTATUS status = OK;

    for (; size > 0; size--)
    {
        if (0 > (status = copyBufToOutput(&ch, 1, pPrtfState)))
            break;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
processFlag(const ubyte *pBufIndex, MprtfState *pPrtfState, ubyte4 *pRetIndex)
{
    MSTATUS status = OK;
    ubyte4  index = 0;
    ubyte   ch = 0;

    while (0 != (ch = *(pBufIndex + index)))
    {
        switch (ch)
        {
        case '+':
            SET_FLAG(pPrtfState, FLAG_PLUS_SIGN);
            break;
        case '-':
            SET_FLAG(pPrtfState, FLAG_LEFT_ALIGN);
            break;
        case ' ':
            SET_FLAG(pPrtfState, FLAG_SPACE);
            break;
        case '0':
            SET_FLAG(pPrtfState, FLAG_PAD_ZERO);
            break;
        case '#':
            SET_FLAG(pPrtfState, FLAG_ALT_FORM);
            break;
        default:
            goto exit;
        }

        index++;
    }

exit:
    *pRetIndex = index;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
processWidthPrec(const ubyte *pBufIndex, intBoolean isWidth, MprtfState *pPrtfState, ubyte4 *pRetIndex)
{
    MSTATUS     status = OK;
    ubyte4      index = 0;
    ubyte       ch;
    intBoolean  isOverflow = FALSE;

    DT_S_INT    tmpVal = 0;
    DT_S_INT    tmpPrev = 0;

    if ('*' == *pBufIndex)
    {
        tmpVal = va_arg(GET_VA_LIST(pPrtfState), DT_S_INT);

        if (0 > tmpVal)
        {
            if (isWidth)
            {
                SET_FLAG(pPrtfState, FLAG_LEFT_ALIGN);
                tmpVal = tmpVal * (-1);
            }
            else
                tmpVal = (-1);
        }

        index++;

        goto exit;
    }

    while (0 != (ch = *(pBufIndex + index)))
    {
        if ('0' <= ch && '9' >= ch)
        {
            index++;

            /* if integer overflowed, continue to get input */
            if (isOverflow)
            {
                continue;
            }

            tmpPrev = tmpVal;
            tmpVal = tmpVal * 10 + (ubyte4)(ch - '0');

            /* integer overflowed, reset value to 0 */
            if (tmpPrev > tmpVal)
            {
                tmpVal = 0;
                isOverflow = TRUE;
            }
        }
        else
            break;
    }

    if ((isWidth && (MAX_WIDTH_VALUE < tmpVal)) ||
        (!isWidth && (MAX_PRECISION_VALUE < tmpVal)))
    {
        tmpVal = 0;
    }

exit:
    if (isWidth)
    {
        MPRINTF_CONV_WIDTH(pPrtfState) = tmpVal;
    }
    else
    {
        MPRINTF_CONV_PRECISION(pPrtfState) = tmpVal;
    }

    *pRetIndex = index;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
processLength(const ubyte *pBufIndex, MprtfState *pPrtfState, ubyte4 *pRetIndex)
{
    MSTATUS status = OK;
    ubyte4  index = 0;
    ubyte   ch = *pBufIndex;

    while (0 != (ch = *(pBufIndex + index)))
    {
        switch (ch)
        {
        case 'h':
            {
                if ('h' == *(pBufIndex + index + 1))
                {
                    SET_LENMOD(pPrtfState, LMOD_HH);
                    index++;
                }
                else
                {
                    SET_LENMOD(pPrtfState, LMOD_H);
                }
                break;
            }
        case 'l':
            {
#ifdef __ENABLE_MPRINTF_LONG_LONG__
                if ('l' == *(pBufIndex + index + 1))
                {
                    SET_LENMOD(pPrtfState, LMOD_LL);
                    index++;
                }
                else
                {
                    SET_LENMOD(pPrtfState, LMOD_L);
                }
#else
                SET_LENMOD(pPrtfState, LMOD_L);
#endif
                break;
            }

#if 0
        case 'j':
            SET_LENMOD(pPrtfState, LMOD_J);
            break;
        case 'z':
            SET_LENMOD(pPrtfState, LMOD_Z);
            break;
        case 't':
            SET_LENMOD(pPrtfState, LMOD_T);
            break;
        case 'L':
            SET_LENMOD(pPrtfState, LMOD_BL);
            break;
#endif

        default:
            goto exit;
        }

        index++;
    } /* while (0 != (ch = *(pBufIndex + index))) */

exit:
    *pRetIndex = index;

    return status;
}


/*------------------------------------------------------------------*/

/* convert integer to string, return number of bytes used (not include leading zeros) */
static ubyte4
getSpaceRequiredInt(Integer *argInt, ubyte4 radix, ubyte4 numBits)
{
    ubyte4  spaceRequired = 0;
    ubyte4  i;
    ubyte   ch;
    ubyte   mask = 0;

#ifdef __ENABLE_MPRINTF_LONG_LONG__
    DT_U_LONG_LONG j;
#endif

    if (0 == radix || NULL == argInt)
        return 0;


    if (0 < numBits)
    {
        spaceRequired = (argInt->numBytes * 8) / numBits;

        if (0 != ((argInt->numBytes * 8) % numBits))
            spaceRequired++;

        mask = 0xff >> (8 - numBits);
    }

    if (8 > argInt->numBytes)
    {
        if (0 < numBits)
        {
            for (i = spaceRequired; i > 0; i--)
            {
                ch = (ubyte)((argInt->value.uLong >> ((i - 1) * numBits)) & mask);

                if (0 == ch)
                    spaceRequired--;
                else
                    break;
            }
        }
        else if (0 == numBits)
        {
            for (i = argInt->value.uLong; i != 0; i /= radix)
                spaceRequired++;
        }
    }
#ifdef __ENABLE_MPRINTF_LONG_LONG__
    else
    {
        if (0 < numBits)
        {
            for (i = spaceRequired; i > 0; i--)
            {
                ch = (ubyte)((argInt->value.uLonglong >> ((i - 1) * numBits)) & mask);

                if (0 == ch)
                    spaceRequired--;
                else
                    break;
            }
        }
        else if (0 == numBits)
        {
            for (j = argInt->value.uLonglong; j != 0; j /= 10)
                spaceRequired++;
        }
    }
#endif

    if (0 == spaceRequired)
        spaceRequired = 1;

    return spaceRequired;
}


/*------------------------------------------------------------------*/

static MSTATUS
processInteger(Integer *argInt, MprtfState *pPrtfState)
{
    MSTATUS         status = OK;
    intBoolean      isLeftAlg = FALSE;
    intBoolean      isPrecision = TRUE;
    intBoolean      isPositive = TRUE;
    intBoolean      isZero = FALSE;
    sbyte4          spaceRequired = 0;
    ubyte4          i;
    ubyte           ch;
    ubyte           signCh = 0;
    ubyte           padCh;
    ubyte           specifier;
    sbyte4          padLen;
    sbyte4          headingLen = 0;
    ubyte           charStore[3] = {'0', 'x', 'a'};
    sbyte4          tmpPrecision;
    sbyte4          tmpWidth;
    ubyte*          tmpBufIndex;


    specifier = MPRINTF_CONV_SPEC(pPrtfState);
    DIGI_MEMSET(pPrtfState->convBuf, 0, CONV_BUFLEN);

    /* convert negative integer to positive, only applies to signed integer */
    if (8 > argInt->numBytes)
    {
        if (('i' == specifier) && (0 > argInt->value.sLong))
        {
            isPositive = FALSE;
            argInt->value.sLong = argInt->value.sLong * (-1);
        }
        else if (0 == argInt->value.sLong)
        {
            isZero = TRUE;
        }
    }
#ifdef __ENABLE_MPRINTF_LONG_LONG__
    else if (8 == argInt->numBytes)
    {
        if (('i' == specifier) && (0 > argInt->value.sLonglong))
        {
            isPositive = FALSE;
            argInt->value.sLonglong = argInt->value.sLonglong * (-1);
        }
        else if (0 == argInt->value.sLonglong)
        {
            isZero = TRUE;
        }
    }
#endif

    if ('p' == specifier)
    {
        isZero = FALSE;
        specifier = 'x';
    }

    if (0 > (tmpWidth = MPRINTF_CONV_WIDTH(pPrtfState)))
    {
        tmpWidth = 0;
    }

    if (0 > (tmpPrecision = MPRINTF_CONV_PRECISION(pPrtfState)))
    {
        tmpPrecision = 0;
        isPrecision = FALSE;
    }

    /* calculate amount of bytes/space required for a converted number */
    if ('i' == specifier || 'u' == specifier)
    {
        spaceRequired = getSpaceRequiredInt(argInt, 10, 0);
    }
    else if ('x' == specifier || 'X' == specifier)
    {
        spaceRequired = getSpaceRequiredInt(argInt, 16, 4);

        if (!isZero && (IS_FLAG_ALT_FORM(pPrtfState)))
        {
            headingLen = 2;
        }

        if ('X' == specifier)
        {
            charStore[1] =  'X';
            charStore[2] =  'A';
        }
    }
    else if ('o' == specifier)
    {
        spaceRequired = getSpaceRequiredInt(argInt, 4, 3);

        if (!isZero && (IS_FLAG_ALT_FORM(pPrtfState)) &&
            (spaceRequired >= tmpPrecision))
        {
            headingLen = 1;
        }
    }

    /* simple error check */
    if (CONV_BUFLEN < spaceRequired)
        return ERR_MPRINTF_INVALID_LENGTH;

    /* if number and precsion are zero, don't print zero */
    if (isZero && (0 == MPRINTF_CONV_PRECISION(pPrtfState)))
    {
        spaceRequired = 0;

        if (('o' == specifier) && (IS_FLAG_ALT_FORM(pPrtfState)))
            headingLen = 1;
    }

    if (IS_FLAG_LEFT_ALIGN(pPrtfState))
    {
        isLeftAlg = TRUE;
    }

    /* calculate padding length */
    padLen = tmpWidth - headingLen - ((tmpPrecision > spaceRequired) ? tmpPrecision : spaceRequired);

    if ('i' == specifier)
    {
        if (!isPositive)
        {
            signCh = '-';
            padLen--;
        }
        else if (IS_FLAG_PLUS_SIGN(pPrtfState))
        {
            signCh = '+';
            padLen--;
        }
        else if (IS_FLAG_SPACE(pPrtfState))
        {
            signCh = ' ';
            padLen--;
        }
    }

    padCh = (IS_FLAG_PAD_ZERO(pPrtfState)) ? '0' : ' ';

    /* add padding before sign */
    if (!isLeftAlg && (0 < padLen) && (isPrecision || ' ' == padCh))
    {
        if (OK > (status = addPadding(' ', padLen, pPrtfState)))
            goto exit;
    }

    /* add "0x" for hex, "o" for octect, " " for int */
    if (('x' == specifier) || ('X' == specifier))
    {
        if (2 == headingLen)
            status = copyBufToOutput(charStore, 2, pPrtfState);
    }
    else if ('o' == specifier)
    {
        if (1 == headingLen)
            status = copyBufToOutput(charStore, 1, pPrtfState);
    }
    else if ('i' == specifier)
    {
        if (0 != signCh)
            status = copyBufToOutput(&signCh, 1, pPrtfState);
    }

    if (OK > status)
        goto exit;


    /* add padding after sign */
    if (!isLeftAlg && (0 < padLen) && !isPrecision && ('0' == padCh))
    {
        if (OK > (status = addPadding('0', padLen, pPrtfState)))
            goto exit;
    }

    /* pad '0' if precision is greater than required space */
    if (spaceRequired < tmpPrecision)
    {
        if (OK > (status = addPadding('0', tmpPrecision - spaceRequired, pPrtfState)))
            goto exit;
    }

    /* convert and print number */
    if (8 > argInt->numBytes)
    {
        DT_U_LONG argNum = argInt->value.uLong;

        if ('i' == specifier || 'u' == specifier)
        {
            tmpBufIndex = pPrtfState->convBuf;

            for (i = spaceRequired; i > 0; i--)
            {
                ch = (ubyte)((argNum % 10) + '0');
                *(tmpBufIndex + i - 1) = ch;
                argNum /= 10;
            }

            if (OK > (status = copyBufToOutput(pPrtfState->convBuf, spaceRequired, pPrtfState)))
                goto exit;
        }
        else if ('x' == specifier || 'X' == specifier)
        {
            for (i = spaceRequired; i > 0; i--)
            {
                ch = (ubyte)((argNum >> ((i - 1) * 4)) & 0xf);

                if (ch >= 10)
                    ch = (ch - 10) + charStore[2];
                else
                    ch = ch + '0';

                if (OK > (status = copyBufToOutput(&ch, 1, pPrtfState)))
                    goto exit;
            }
        }
        else if ('o' == specifier)
        {
            for (i = spaceRequired; i > 0; i--)
            {
                ch = (ubyte)((argNum >> ((i - 1) * 3)) & 0x7);

                ch = ch + '0';

                if (OK > (status = copyBufToOutput(&ch, 1, pPrtfState)))
                    goto exit;
            }
        }
    }
#ifdef __ENABLE_MPRINTF_LONG_LONG__
    else
    {
        DT_U_LONG_LONG argNum = argInt->value.uLonglong;

        if ('i' == specifier || 'u' == specifier)
        {
            tmpBufIndex = pPrtfState->convBuf;

            for (i = spaceRequired; i > 0; i--)
            {
                ch = (char)((argNum % 10) + '0');
                *(tmpBufIndex + i - 1) = ch;
                argNum /= 10;
            }

            if (OK > (status = copyBufToOutput(pPrtfState->convBuf, spaceRequired, pPrtfState)))
                goto exit;
        }
        else if ('x' == specifier || 'X' == specifier)
        {
            for (i = spaceRequired; i > 0; i--)
            {
                ch = (ubyte)((argNum >> ((i - 1) * 4)) & 0xf);

                if (ch >= 10)
                    ch = (ch - 10) + charStore[2];
                else
                    ch = ch + '0';

                if (OK > (status = copyBufToOutput(&ch, 1, pPrtfState)))
                    goto exit;
            }
        }
        else if ('o' == specifier)
        {
            for (i = spaceRequired; i > 0; i--)
            {
                ch = (ubyte)((argNum >> ((i - 1) * 3)) & 0x7);

                ch = ch + '0';

                if (OK > (status = copyBufToOutput(&ch, 1, pPrtfState)))
                    goto exit;
            }
        }
    }
#endif

    if (isLeftAlg && padLen > 0)
    {
        status = addPadding(' ', padLen, pPrtfState);
    }

exit:

    if (OK > status)
        DEBUG_ERROR(DEBUG_COMMON, "MPRINTF:processInteger() returns status = ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
getIntFromArg(Integer *argInt, MprtfState *pPrtfState)
{
    MSTATUS status = OK;
    ubyte4  tmpInt;
    ubyte   ch;

    ch = MPRINTF_CONV_SPEC(pPrtfState);

    switch (MPRINTF_CONV_LENMOD(pPrtfState))
    {
    case LMOD_NONE:
        {
            tmpInt = va_arg(GET_VA_LIST(pPrtfState), DT_U_INT);

            if ('i' == ch)
                argInt->value.sLong = (DT_S_INT)tmpInt;
            else
                argInt->value.uLong = (DT_U_INT)tmpInt;

            /* machines dependent, 2 or 4 bytes */
            argInt->numBytes = sizeof(DT_S_INT);

            break;
        }

    case LMOD_HH:
        {
            tmpInt = va_arg(GET_VA_LIST(pPrtfState), DT_U_INT);

            if ('i' == ch)
                argInt->value.sLong = (DT_S_CHAR)tmpInt;
            else
                argInt->value.uLong = (DT_U_CHAR)tmpInt;

            argInt->numBytes = 1;
            break;
        }

    case LMOD_H:
        {
            tmpInt = va_arg(GET_VA_LIST(pPrtfState), DT_U_INT);

            if ('i' == ch)
                argInt->value.sLong = (DT_S_SHORT)tmpInt;
            else
                argInt->value.uLong = (DT_U_SHORT)tmpInt;

            argInt->numBytes = 2;
            break;
        }

    case LMOD_L:
        {
            argInt->value.sLong = va_arg(GET_VA_LIST(pPrtfState), DT_S_LONG);
            argInt->numBytes = 4;
            break;
        }

#ifdef __ENABLE_MPRINTF_LONG_LONG__
    case LMOD_LL:
        {
            argInt->value.sLonglong = va_arg(GET_VA_LIST(pPrtfState), DT_S_LONG_LONG);
            argInt->numBytes = 8;
            break;
        }
#endif

    default:
        status = ERR_MPRINTF_INVALID_LENGTH_MODIFIER;
        break;
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_COMMON, "MPRINTF:getIntFromArg() returns status = ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MPRINTF_FLOAT__

#if 0
static void PrintVLong( const char* msg, const vlong* v)
{
    ubyte* buffer;
    sbyte4 bufferLen;
    sbyte4 i,j;

    VLONG_byteStringFromVlong(v, NULL, &bufferLen);

    buffer = MALLOC( bufferLen+1);

    VLONG_byteStringFromVlong(v, buffer, &bufferLen);

    printf("\n%s\n", msg);
    for (i = 0; i < bufferLen; ++i)
    {
        if ( buffer[i])
        {
            break;
        }
    }

    for (j=0; i < bufferLen; ++i, ++j)
    {
        printf("%02X", buffer[i]);
        if ( 15 == j % 16)
        {
            printf("\n");
        }
    }
    printf("\n");

    FREE(buffer);
}
#endif


/*------------------------------------------------------------------*/

static MSTATUS
processDouble(DT_DOUBLE num, MprtfState *pPrtfState)
{
    MSTATUS     status = OK;
    uNum        n;
    ubyte4      mantissa[2];
    sbyte4      exponent;
    sbyte4      sign;
    sbyte4      result;
    sbyte4      k = 0;
    sbyte4      digit;
    intBoolean  isRound = 0;
    intBoolean  tc1 = 0;
    intBoolean  tc2 = 0;
    vlong*      pvMantissa = 0;
    vlong*      pvConstTen = 0;
    vlong*      pvNum1 = 0;
    vlong*      pvBE = 0;
    vlong*      pvR = 0;
    vlong*      pvS = 0;
    vlong*      pvMP = 0;
    vlong*      pvMM = 0;
    vlong*      pvQuo = 0;
    vlong*      pvRem = 0;
    vlong*      pvTmp = 0;
    ubyte*      tmpBufIndex;
    ubyte4      digitCount = 0;


    DIGI_MEMSET(pPrtfState->convBuf, 0, CONV_BUFLEN);

    tmpBufIndex = pPrtfState->convBuf;

    n.f = num;

    /* assuming double is in IEEE 754 format */
#ifndef MOC_BIG_ENDIAN
    mantissa[0] = n.dword[1];
    mantissa[1] = n.dword[0];
#else
    mantissa[0] = n.dword[0];
    mantissa[1] = n.dword[1];
#endif

    exponent = GET_EXPONENT(mantissa[0]);
    sign = GET_SIGN(mantissa[0]);

    mantissa[0] = mantissa[0] & MASK_MANT;


    if (0 == exponent)
    {
        if (0 == mantissa[1] && 0 == mantissa[0])
        {
            *tmpBufIndex = '0';
            goto exit;
        }
        else
        {
            /* denormalized number - hidden bit is 0 */
            exponent = -1074;
        }
    }
    else if (DBL_EMAX == exponent)
    {
        if (0 == mantissa[1] && 0 == mantissa[0])
        {
            *tmpBufIndex = 'i';
            goto exit;
        }
        else
        {
            *tmpBufIndex = 'n';
            goto exit;
        }
    }
    else
    {
        /* normailzed number - hidden bit is 1 */
        mantissa[0] = mantissa[0] | MASK_HIDDEN_BIT;
        exponent = exponent - DBL_BIAS - DBL_PREC;
    }

    /* is mantissa even or odd? */
    isRound = (mantissa[1] & 1) ? 0 : 1;

    /* f */
    if (OK > (status = VLONG_vlongFromUByte4String(mantissa, 2, &pvMantissa)))
        goto exit;

    /* pvConstTen = 10 */
    if (OK > (status = VLONG_makeVlongFromUnsignedValue(10, &pvConstTen, NULL)))
        goto exit;

    /* pvNum1 = b^(p-1) */
    if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &pvNum1, NULL)))
        goto exit;

    if (OK > (status = VLONG_shlXvlong(pvNum1, DBL_PREC - 1)))
        goto exit;

    if (0 <= exponent)
    {
        /* be = b^e */
        if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &pvBE, NULL)))
            goto exit;

        if (OK > (status = VLONG_shlXvlong(pvBE, exponent)))
            goto exit;

        /* r = f * b^e * 2 */
        if (OK > (status = VLONG_allocVlong(&pvR, NULL)))
            goto exit;

        if (OK > (status = VLONG_unsignedMultiply(pvR, pvMantissa, pvBE)))
            goto exit;

        if (OK > (status = VLONG_shlVlong(pvR)))
            goto exit;

        /* s = 2 */
        if (OK > (status = VLONG_makeVlongFromUnsignedValue(2, &pvS, NULL)))
            goto exit;

        /* m+ = b^e */
        if (OK > (status = VLONG_makeVlongFromVlong(pvBE, &pvMP, NULL)))
            goto exit;

        /* m- = b^e */
        if (OK > (status = VLONG_makeVlongFromVlong(pvBE, &pvMM, NULL)))
            goto exit;

        /* X == Y = 0; X > Y == +1; X < Y == -1*/
        result = VLONG_compareSignedVlongs(pvMantissa, pvNum1);

        /* f == b^(p-1) */
        if (0 == result)
        {
            if (OK > (status = VLONG_shlVlong(pvR)))
                goto exit;

            if (OK > (status = VLONG_shlVlong(pvS)))
                goto exit;

            if (OK > (status = VLONG_shlVlong(pvMP)))
                goto exit;
        }
    }
    else
    {
        /* r = f * 2 */
        if (OK > (status = VLONG_makeVlongFromVlong(pvMantissa, &pvR, NULL)))
            goto exit;

        if (OK > (status = VLONG_shlVlong(pvR)))
            goto exit;

        /* s = b^(-e) * 2 */
        if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &pvS, NULL)))
            goto exit;

        if (OK > (status = VLONG_shlXvlong(pvS, exponent * (-1) + 1)))
            goto exit;

        /* m+ = 1 */
        if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &pvMP, NULL)))
            goto exit;

        /* m- = 1 */
        if (OK > (status = VLONG_makeVlongFromUnsignedValue(1, &pvMM, NULL)))
            goto exit;

        result = VLONG_compareSignedVlongs(pvMantissa, pvNum1);

        /* e > min exp && f == b^(p-1) */
        if (-1075 < exponent && 0 == result)
        {
            if (OK > (status = VLONG_shlVlong(pvR)))
                goto exit;

            if (OK > (status = VLONG_shlVlong(pvS)))
                goto exit;

            if (OK > (status = VLONG_shlVlong(pvMP)))
                goto exit;
        }
    }

    if (OK > (status = VLONG_allocVlong(&pvTmp, NULL)))
        goto exit;

    /* compute k (base 10 exponent) */
    while(1)
    {
        if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvMP, pvConstTen)))
            goto exit;

        if (OK > (status = VLONG_addSignedVlongs(pvTmp, pvR, NULL)))
            goto exit;

        result = VLONG_compareSignedVlongs(pvTmp, pvS);

        if ((!isRound && (0 == result || -1 == result)) || (-1 == result))
        {
            if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvR, pvConstTen)))
                goto exit;

            if (OK > (status = VLONG_copySignedValue(pvR, pvTmp)))
                goto exit;

            if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvMP, pvConstTen)))
                goto exit;

            if (OK > (status = VLONG_copySignedValue(pvMP, pvTmp)))
                goto exit;

            if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvMM, pvConstTen)))
                goto exit;

            if (OK > (status = VLONG_copySignedValue(pvMM, pvTmp)))
                goto exit;

            k = k - 1;
        }
        else
            break;
    }

    if (OK > (status = VLONG_copySignedValue(pvNum1, pvR)))
        goto exit;

    if (OK > (status = VLONG_addSignedVlongs(pvNum1, pvMP, NULL)))
        goto exit;

    while (1)
    {
        result = VLONG_compareSignedVlongs(pvNum1, pvS);

        if ((isRound && (0 == result || 1 == result)) || (1 == result))
        {
            if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvS, pvConstTen)))
                goto exit;

            if (OK > (status = VLONG_copySignedValue(pvS, pvTmp)))
                goto exit;

            k = k + 1;
        }
        else
            break;
    }

    if (OK > (status = VLONG_allocVlong(&pvQuo, NULL)))
        goto exit;

    if (OK > (status = VLONG_allocVlong(&pvRem, NULL)))
        goto exit;

    while(digitCount < CONV_BUFLEN)
    {
        if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvR, pvConstTen)))
            goto exit;

        if (OK > (status = VLONG_unsignedDivide(pvQuo, pvTmp, pvS, pvRem, NULL)))
            goto exit;

        if (OK > (status = VLONG_copySignedValue(pvR, pvRem)))
            goto exit;

        if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvMP, pvConstTen)))
            goto exit;

        if (OK > (status = VLONG_copySignedValue(pvMP, pvTmp)))
            goto exit;

        if (OK > (status = VLONG_unsignedMultiply(pvTmp, pvMM, pvConstTen)))
            goto exit;

        if (OK > (status = VLONG_copySignedValue(pvMM, pvTmp)))
            goto exit;

        result = VLONG_compareSignedVlongs(pvR, pvMM);

        if ((isRound && 0 == result) || (-1 == result))
        {
            tc1 = 1;
        }

        if (OK > (status = VLONG_copySignedValue(pvTmp, pvR)))
            goto exit;

        if (OK > (status = VLONG_addSignedVlongs(pvTmp, pvMP, NULL)))
            goto exit;

        result = VLONG_compareSignedVlongs(pvTmp, pvS);

        if ((isRound && 0 == result) || (1 == result))
        {
            tc2 = 1;
        }

        if (OK > (status = VLONG_copySignedValue(pvTmp, pvR)))
            goto exit;

        if (OK > (status = VLONG_shlVlong(pvTmp)))
            goto exit;

        result = VLONG_compareSignedVlongs(pvTmp, pvS);

        digit = VLONG_getVlongUnit(pvQuo, 0);

        if (!tc1)
        {
            if (!tc2)
            {
                *tmpBufIndex++ = (ubyte)(digit + '0');
                digitCount++;
                continue;
            }
            digit++;
        }
        else if (!tc2 || -1 == result)
            ;
        else
            digit++;

        *tmpBufIndex++ = (ubyte)(digit + '0');

        break;
    }

    if (CONV_BUFLEN <= digitCount)
    {
        status = ERR_MPRINTF_BUFFER_FULL;
        goto exit;
    }

    pPrtfState->exponent = k;
    pPrtfState->sign = sign;

exit:
    VLONG_freeVlong(&pvMantissa, NULL);
    VLONG_freeVlong(&pvConstTen, NULL);
    VLONG_freeVlong(&pvNum1, NULL);
    VLONG_freeVlong(&pvBE, NULL);
    VLONG_freeVlong(&pvR, NULL);
    VLONG_freeVlong(&pvS, NULL);
    VLONG_freeVlong(&pvMP, NULL);
    VLONG_freeVlong(&pvMM, NULL);
    VLONG_freeVlong(&pvQuo, NULL);
    VLONG_freeVlong(&pvRem, NULL);
    VLONG_freeVlong(&pvTmp, NULL);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
formatDouble(MprtfState *pPrtfState)
{
    MSTATUS     status = OK;
    ubyte*      pBufIndex;
    sbyte4      bufLen;
    sbyte4      exponent;
    ubyte       specifier;
    sbyte4      precision;
    sbyte4      width;
    sbyte4      spaceRequired = 0;
    sbyte4      numExpDigit = 0;
    sbyte4      powerOfTen = 1;
    intBoolean  isNegative;
    intBoolean  isZero = 0;
    sbyte4      padLen = 0;
    sbyte4      zeroPadLen = 0;
    ubyte       ch = 0;
    sbyte4      digits = 0;


    pBufIndex = pPrtfState->convBuf;
    bufLen = (sbyte4)DIGI_STRLEN((sbyte *)pBufIndex);
    exponent = pPrtfState->exponent;
    isNegative = pPrtfState->sign;

    specifier = MPRINTF_CONV_SPEC(pPrtfState);
    precision = MPRINTF_CONV_PRECISION(pPrtfState);
    width = MPRINTF_CONV_WIDTH(pPrtfState);

    /* set default precision to 6 */
    if (-1 == precision)
    {
        precision = 6;
    }

    if (-4 > exponent || precision <= exponent)
    {
        if ('g' == specifier)
            specifier = 'e';
        else if ('G' == specifier)
            specifier = 'E';
    }
    else
    {
        if ('g' == specifier)
            specifier = 'f';
        else if ('G' == specifier)
            specifier = 'F';
    }

    if ( -1 == MPRINTF_CONV_PRECISION(pPrtfState) &&
         ('g' == MPRINTF_CONV_SPEC(pPrtfState) ||
          'G' == MPRINTF_CONV_SPEC(pPrtfState)) )
    {
        sbyte4 i;

        bufLen = (6 > bufLen) ? bufLen : 6;

        for (i=bufLen-1; i>=0; i--)
        {
            if ('0' != pBufIndex[i])
                break;
        }

        bufLen = i + 1;

        if ('f' == specifier || 'F' == specifier)
        {
            if (0 < exponent)
            {
                digits = (bufLen < exponent) ? 0 : (bufLen - exponent);
            }
            else
            {
                digits = exponent * (-1) + bufLen;
            }
        }

        if ('e' == specifier || 'E' == specifier)
        {
            /* exponent is always 1 */
            digits = (bufLen < 1) ? 0 : (bufLen - 1);
        }

        if (1 == bufLen && '0' == *pBufIndex)
            precision = 0;
        else
            precision = (6 > digits) ? digits : 6;
    }

    /* need a space for sign */
    if (isNegative ||
        IS_FLAG_PLUS_SIGN(pPrtfState) ||
        IS_FLAG_SPACE(pPrtfState))
    {
        spaceRequired++;
    }

    if ('i' == *pBufIndex)
    {
        spaceRequired = spaceRequired + 3;

        goto nextStep;
    }

    if ('n' == *pBufIndex)
    {
        spaceRequired = spaceRequired + 3;

        goto nextStep;
    }

    if ('0' == *pBufIndex)
        isZero = 1;

    if ((0 >= exponent) || ('e' == specifier || 'E' == specifier))
    {
        spaceRequired = 1 + 1 + precision;
    }
    else if (0 < exponent)
    {
        spaceRequired = exponent + 1 + precision;
    }

    if (!isZero && ('e' == specifier || 'E' == specifier))
        exponent--;

    /* do not display radix character ('.') if precsion is 0 */
    if (!IS_FLAG_ALT_FORM(pPrtfState) && 0 == precision)
        spaceRequired--;

    if (0 > exponent)
        exponent = exponent * (-1);

    if (400 < exponent)
    {
        status = ERR_MPRINTF_DOUBLE_EXPONENT;
        goto exit;
    }

    if (0 == exponent)
        numExpDigit++;

    while (0 < exponent)
    {
        exponent = exponent / 10;
        powerOfTen = powerOfTen * 10;
        numExpDigit++;
    }

    /* reset exponent */
    exponent = pPrtfState->exponent;

    if ('e' == specifier || 'E' == specifier)
    {
        if (2 < numExpDigit)
            spaceRequired = spaceRequired + numExpDigit + 2;
        else
            spaceRequired = spaceRequired + 2 + 2;
    }

nextStep:

    if (0 < width)
        padLen = width - spaceRequired;

    if (0 < padLen && !(IS_FLAG_LEFT_ALIGN(pPrtfState)))
    {
        if (IS_FLAG_PAD_ZERO(pPrtfState))
            status = addPadding('0', padLen, pPrtfState);
        else
            status = addPadding(' ', padLen, pPrtfState);

        if (OK > status)
            goto exit;
    }

    if (isNegative)
    {
        ch = '-';
    }
    else
    {
        if (IS_FLAG_PLUS_SIGN(pPrtfState))
            ch = '+';
        else if (IS_FLAG_SPACE(pPrtfState))
            ch = ' ';
    }

    if (0 != ch)
    {
        if (OK > (status = copyBufToOutput(&ch, 1, pPrtfState)))
            goto exit;
    }

    if ('i' == *pBufIndex)
    {
        if ('e' == specifier || 'f' == specifier)
            pBufIndex = (ubyte *)"inf";
        else if ('E' == specifier || 'F' == specifier)
            pBufIndex = (ubyte *)"INF";

        if (OK > (status = copyBufToOutput(pBufIndex, 3, pPrtfState)))
            goto exit;

        goto suffixPad;
    }

    if ('n' == *pBufIndex)
    {
        if ('e' == specifier || 'f' == specifier)
            pBufIndex = (ubyte *)"nan";
        else if ('E' == specifier || 'F' == specifier)
            pBufIndex = (ubyte *)"NAN";

        if (OK > (status = copyBufToOutput(pBufIndex, 3, pPrtfState)))
            goto exit;

        goto suffixPad;
    }

    if ('e' == specifier || 'E' == specifier)
        exponent = 1;

    if (0 < exponent)
    {
        if (bufLen < exponent)
        {
            status = copyBufToOutput(pBufIndex, bufLen, pPrtfState);

            if (OK > status)
                goto exit;

            status = addPadding('0', exponent - bufLen, pPrtfState);
        }
        else
        {
            status = copyBufToOutput(pBufIndex, exponent, pPrtfState);
        }

        if (OK > status)
            goto exit;
    }
    else
    {
        if (OK > (status = copyBufToOutput((ubyte *)"0", 1, pPrtfState)))
            goto exit;
    }

    if (IS_FLAG_ALT_FORM(pPrtfState) || 0 != precision)
    {
        if (OK > (status = copyBufToOutput((ubyte *)".", 1, pPrtfState)))
            goto exit;
    }

    if (0 < exponent)
    {
        if (bufLen < exponent)
        {
            if (0 < precision)
                status = addPadding('0', precision, pPrtfState);
        }
        else
        {
            if ((bufLen - exponent) < precision)
            {
                status = copyBufToOutput(pBufIndex + exponent, bufLen - exponent, pPrtfState);

                if (OK > status)
                    goto exit;

                status = addPadding('0', precision - (bufLen - exponent), pPrtfState);
            }
            else
                status = copyBufToOutput(pBufIndex + exponent, precision, pPrtfState);
        }

        if (OK > status)
            goto exit;
    }
    else
    {
        zeroPadLen = exponent * (-1);

        if (precision <= zeroPadLen)
        {
            status = addPadding('0', precision, pPrtfState);
        }
        else
        {
            status = addPadding('0', zeroPadLen, pPrtfState);

            if (OK > status)
                goto exit;

            if ((precision - zeroPadLen) <= bufLen)
                status = copyBufToOutput(pBufIndex, precision - zeroPadLen, pPrtfState);
            else
                status = copyBufToOutput(pBufIndex, bufLen, pPrtfState);

            if (OK > status)
                goto exit;

            status = addPadding('0', precision - zeroPadLen - bufLen, pPrtfState);
        }

        if (OK > status)
            goto exit;
    }

    /* reset exponent */
    exponent = pPrtfState->exponent;

    if ('e' == specifier || 'E' == specifier)
    {
        if (!isZero)
            exponent--;

        /* e or E */
        if (OK > (status = copyBufToOutput(&specifier, 1, pPrtfState)))
            goto exit;

        if (0 > exponent)
        {
            exponent = exponent * (-1);
            ch = '-';
        }
        else
            ch = '+';

        /* exponent sign */
        if (OK > (status = copyBufToOutput(&ch, 1, pPrtfState)))
            goto exit;

        if (2 > numExpDigit)
        {
            if (OK > (status = copyBufToOutput((ubyte *)"0", 1, pPrtfState)))
                goto exit;
        }

        if (0 == exponent)
        {
            if (OK > (status = copyBufToOutput((ubyte *)"0", 1, pPrtfState)))
                goto exit;

            numExpDigit--;
        }

        while (0 < numExpDigit)
        {
            powerOfTen = powerOfTen / 10;

            if (1 > powerOfTen)
            {
                status = -1; /* !!! error */
                goto exit;
            }

            ch = (ubyte)((exponent / powerOfTen) % 10 + '0');

            if (OK > (status = copyBufToOutput(&ch, 1, pPrtfState)))
                goto exit;

            numExpDigit--;
        }
    }

suffixPad:

    if (0 < padLen && !(IS_FLAG_PAD_ZERO(pPrtfState)) && IS_FLAG_LEFT_ALIGN(pPrtfState))
    {
        if (OK > (status = addPadding(' ', padLen, pPrtfState)))
            goto exit;
    }

exit:
    return status;
}

#endif /* __ENABLE_MPRINTF_FLOAT__ */


/*------------------------------------------------------------------*/

static MSTATUS
processSpecifier(const ubyte *pBufIndex, MprtfState *pPrtfState)
{
    MSTATUS     status = OK;
    ubyte       ch;

    switch (ch = *pBufIndex)
    {
    case 'd': /* FALL-THROUGH */
    case 'i':
    case 'u':
    case 'o':
    case 'x':
    case 'X':
    case 'p':
        {
            Integer argInt;

            DIGI_MEMSET((ubyte *)&argInt, 0x00, sizeof(Integer));

            if ('d' == ch)
                ch = 'i';

            if ('p' == ch)
            {
                SET_FLAG(pPrtfState, FLAG_ALT_FORM);
                SET_LENMOD(pPrtfState, LMOD_NONE);
            }

            MPRINTF_CONV_SPEC(pPrtfState) = ch;

            if (OK > (status = getIntFromArg(&argInt, pPrtfState)))
                goto exit;

            if (OK > (status = processInteger(&argInt, pPrtfState)))
                goto exit;

            break;
        }

    case 's': /* FALL-THROUGH */
    case 'c':
    case '%':
    case 'm':
        {
            ubyte           argCh;
            const ubyte*    argString = NULL;
            ubyte4          strLen = 0;
            sbyte4          padLen;
            ubyte           padCh;

            padCh = (IS_FLAG_PAD_ZERO(pPrtfState)) ? '0' : ' ';
            padLen = MPRINTF_CONV_WIDTH(pPrtfState);

            if ('c' == ch)
            {
                argCh = (DT_U_CHAR)va_arg(GET_VA_LIST(pPrtfState), DT_S_INT);

                argString = &argCh;
                strLen = 1;
            }
            else if ('%' == ch)
            {
                ch = 'c';
                argCh = '%';

                argString = &argCh;
                strLen = 1;
            }
#ifdef __ENABLE_LOOKUP_TABLE__
            else if ('m' == ch)
            {
                MSTATUS errCode;

                errCode = (MSTATUS)va_arg(GET_VA_LIST(pPrtfState), DT_S_INT);

                argString = (ubyte *)MERROR_lookUpErrorCode(errCode);

                if (NULL == argString)
                    argString = (ubyte *)"UNKNOWN_ERROR";

                strLen = DIGI_STRLEN((sbyte *)argString);
            }
#endif
            else
            {
                argString = va_arg(GET_VA_LIST(pPrtfState), const ubyte *);
                strLen = DIGI_STRLEN((sbyte *)argString);

                if ((0 <= MPRINTF_CONV_PRECISION(pPrtfState)) &&
                    (strLen > MPRINTF_CONV_PRECISION(pPrtfState)))
                {
                    strLen = MPRINTF_CONV_PRECISION(pPrtfState);
                }
            }

            padLen = padLen - strLen;

            if ((0 < padLen) && !(IS_FLAG_LEFT_ALIGN(pPrtfState)))
            {
                if (OK > (status = addPadding(padCh, padLen, pPrtfState)))
                    goto exit;
            }

            if (OK > (status = copyBufToOutput(argString, strLen, pPrtfState)))
                goto exit;

            if ((0 < padLen) && IS_FLAG_LEFT_ALIGN(pPrtfState))
            {
                if (OK > (status = addPadding(' ', padLen, pPrtfState)))
                    goto exit;
            }

            break;
        }

    case 'n':
        {
            sbyte4* pValue = NULL;

            pValue = (sbyte4*) va_arg(GET_VA_LIST(pPrtfState), DT_PTR);

            if (NULL == pValue)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            *pValue = pPrtfState->numBytesWritten;

            break;
        }

    case 'f': /* FALL-THROUGH */
    case 'F':
    case 'e':
    case 'E':
    case 'g':
    case 'G':
#if 0 /* !!! not yet implemented */
    case 'a':
    case 'A':
#endif
        {
#ifdef __ENABLE_MPRINTF_FLOAT__
            DT_DOUBLE   num;

            num = va_arg(GET_VA_LIST(pPrtfState), DT_DOUBLE);

            MPRINTF_CONV_SPEC(pPrtfState) = ch;

            if (OK > (status = processDouble(num, pPrtfState)))
                goto exit;

            status = formatDouble(pPrtfState);
#endif
            break;
        }

    default:
        status = ERR_MPRINTF_UNKNOWN_SPECIFIER;
        break;
    }

exit:
    /* clear state information */
    resetConversionInfo(pPrtfState);

    if (OK > status)
        DEBUG_ERROR(DEBUG_COMMON, "MPRINTF:processSpecifier() returns status = ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

static intBoolean
charInString(const ubyte *pString, ubyte ch)
{
    ubyte tmpCh;

    while (0 != (tmpCh = *pString))
    {
        if (tmpCh == ch)
            return TRUE;

        pString++;
    }

    return FALSE;
}


/*------------------------------------------------------------------*/

static MSTATUS
lookAhead(const ubyte *pBufIndex, sbyte4 currentState, sbyte4 *pRetState, ubyte4 *pRetIndex)
{
    MSTATUS status = OK;
    ubyte4  index = 0;
    ubyte   ch = *pBufIndex;
    sbyte4  state = currentState;

    if (ST_INVALID == currentState)
    {
        status = ERR_MPRINTF_INVALID_STATE;
        goto exit;
    }

    if (ST_CHAR == state)
    {
        if (0 == ch)
        {
            state = ST_DONE;
            goto exit;
        }

        if ('%' != ch)
        {
            state = ST_CHAR;
            goto exit;
        }
        else
        {
            index++;
            ch = *(pBufIndex + index);
        }
    }

    if (ST_FLAG > state)
    {
        if (charInString((ubyte *)"+- 0#", ch))
        {
            state = ST_FLAG;
            goto exit;
        }
    }

    if (ST_WIDTH > state)
    {
        if (charInString((ubyte *)"123456789*", ch))
        {
            state = ST_WIDTH;
            goto exit;
        }
    }

    if (ST_PRECISION > state)
    {
        if ('.' != ch)
        {
            goto checkLength;
        }
        else
        {
            index++;
            ch = *(pBufIndex + index);
        }

        if (charInString((ubyte *)"0123456789*", ch))
        {
            state = ST_PRECISION;
        }
        else
        {
            state = ST_CHAR;
            status = ERR_MPRINTF_INVALID_FORMAT;
        }

        goto exit;
    }

checkLength:

    if (ST_LENGTH > state)
    {
        if (charInString((ubyte *)"hl", ch))
        {
            state = ST_LENGTH;
            goto exit;
        }
    }

    if (ST_SPECIFIER > state)
    {
        if (charInString((ubyte *)"diuoxXcspfFeEgGn%m", ch))
        {
            state = ST_SPECIFIER;
            goto exit;
        }
    }

    state = ST_CHAR;
    status = ERR_MPRINTF_INVALID_FORMAT;

exit:
    *pRetIndex = index;
    *pRetState = state;

    if (OK > status)
        DEBUG_ERROR(DEBUG_COMMON, "MPRINTF:lookAhead() returns status = ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
BCPRINTF(mocSegDescr *pBufSeg, mocSegDescr **ppRetBufSeg, const ubyte *pFormatString, moc_va_list *pVaList)
{
    sbyte4          status = OK;
    MprtfState      prtfState;

    const ubyte*    pFormatIndex;
    const ubyte*    pConvBufIndex = NULL;
    ubyte4          index = 0;
    sbyte4          state;

    if (NULL == pBufSeg || NULL == pFormatString)
    {
        return ERR_NULL_POINTER;
    }

    if (NULL != ppRetBufSeg)
        *ppRetBufSeg = NULL;

    /* initialization */
    DIGI_MEMSET((ubyte *)&prtfState, 0x00, sizeof(MprtfState));

    pFormatIndex = pFormatString;
    state = ST_CHAR;

    prtfState.pHeadOfSegs = pBufSeg;
    prtfState.pCurrentSeg = pBufSeg;
    
    prtfState.pVaList = pVaList;

    resetConversionInfo(&prtfState);

    /* process input */
    while (ST_DONE != state)
    {
        status = (sbyte4)lookAhead(pFormatIndex, state, &state, &index);

        if ('%' == *pFormatIndex)
            pConvBufIndex = pFormatIndex;

        pFormatIndex = pFormatIndex + index;

        switch (state)
        {
        /* skip static characters */
        case ST_CHAR:
            {
                index = 0;

                if (ERR_MPRINTF_INVALID_FORMAT == status)
                {
                    resetConversionInfo(&prtfState);
                }

                if (OK == status)
                    pConvBufIndex = pFormatIndex;

                while((0 != *pFormatIndex) && ('%' != *pFormatIndex))
                {
                    pFormatIndex++;
                }

                status = (sbyte4)copyBufToOutput(pConvBufIndex, pFormatIndex - pConvBufIndex, &prtfState);

                break;
            }

        case ST_FLAG:
            status = (sbyte4)processFlag(pFormatIndex, &prtfState, &index);
            break;

        case ST_WIDTH:
            status = (sbyte4)processWidthPrec(pFormatIndex, 1, &prtfState, &index);
            break;

        case ST_PRECISION:
            status = (sbyte4)processWidthPrec(pFormatIndex, 0, &prtfState, &index);
            break;

        case ST_LENGTH:
            status = (sbyte4)processLength(pFormatIndex, &prtfState, &index);
            break;

        case ST_SPECIFIER:
            status = (sbyte4)processSpecifier(pFormatIndex, &prtfState);
            break;

        case ST_DONE:
            break;

        default:
            status = ERR_MPRINTF_INVALID_STATE;
            goto exit;
        }

        if (ST_SPECIFIER == state)
        {
            state = ST_CHAR;
            index = 1;
        }

        if (OK > status)
            goto exit;

        pFormatIndex = pFormatIndex + index;

    } /* while (ST_DONE != state) */

    status = (sbyte4)copyBufToOutput((ubyte *)"\0", 1, &prtfState);

    /* return number of bytes printed, excluding '\0' */
    if (0 <= status)
        status = prtfState.numBytesWritten - 1;

    if (NULL != ppRetBufSeg)
    {
        mocSegDescr *pCurSeg = prtfState.pCurrentSeg;

        /* if buffer is used, get the next unused segment */
        if (0 < GET_SEG_BYTES_USED(pCurSeg))
            pCurSeg = GET_NEXT_SEG(pCurSeg);

        *ppRetBufSeg = pCurSeg;
    }

exit:
    if (OK > status)
    {
        clearBuffer(&prtfState);
        DEBUG_ERROR(DEBUG_COMMON, "MPRINTF: returns status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
MPRINTF(mocSegDescr *pBufSeg, mocSegDescr **ppRetBufSeg, const ubyte *pFormatString, ...)
{
    MSTATUS status;
    moc_va_list vaList;

    va_start(vaList.ap, pFormatString);

    status = BCPRINTF(pBufSeg, ppRetBufSeg, pFormatString, &vaList);

    va_end(vaList.ap);

    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_SNPRINTF(sbyte *buffer, sbyte4 bufSize, const ubyte *pFormatString, ...)
{
    MSTATUS         status;
    moc_va_list     vaList;
    mocSegDescr*    singleSeg;

    if (NULL == (singleSeg = (mocSegDescr *)MALLOC(sizeof(mocSegDescr))))
    {
        return ERR_NULL_POINTER;
    }

    DIGI_MEMSET((ubyte *)singleSeg, 0x00, sizeof(mocSegDescr));

    singleSeg->pBuff     = (ubyte *)buffer;
    singleSeg->buffLen   = (0 < bufSize) ? (ubyte4)bufSize : 0;

    va_start(vaList.ap, pFormatString);

    status = BCPRINTF(singleSeg, NULL, pFormatString, &vaList);

    va_end(vaList.ap);

    singleSeg->pBuff     = NULL;
    singleSeg->buffLen   = 0;

    FREE(singleSeg);

    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_VSNPRINTF(sbyte *buffer, sbyte4 bufSize, const ubyte *pFormatString, moc_va_list* ap)
{
    MSTATUS         status;
    mocSegDescr*    singleSeg;

    if (NULL == (singleSeg = (mocSegDescr *)MALLOC(sizeof(mocSegDescr))))
    {
        return ERR_NULL_POINTER;
    }

    DIGI_MEMSET((ubyte *)singleSeg, 0x00, sizeof(mocSegDescr));

    singleSeg->pBuff     = (ubyte *)buffer;
    singleSeg->buffLen   = (0 < bufSize) ? (ubyte4)bufSize : 0;

    status = BCPRINTF(singleSeg, NULL, pFormatString, ap);

    singleSeg->pBuff     = NULL;
    singleSeg->buffLen   = 0;

    FREE(singleSeg);

    return status;
}

#endif /* __ENABLE_DIGICERT_PRINTF__ */
