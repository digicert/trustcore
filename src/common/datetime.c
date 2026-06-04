/*
 * datetime.c
 *
 * Digicert Date Time utility routines
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/datetime.h"

#if (!defined(__DISABLE_DIGICERT_COMMON_DATE_TIME_UTILITY__))

/*-------------------------------------------------------------------------*/

/* The day number algorithm (from alcor.concordia.ca) uses y/4 - y/100 + y/400 to count
 * leap days. This formula assumes year 0 is a leap year (which it is in the proleptic
 * Gregorian calendar). However, our TimeDate struct stores years relative to 1970,
 * and 1970 is NOT a leap year (1970 % 4 = 2). This mismatch causes y/4 to miscount
 * leap days. Fix: use calendar year (y+1970) for leap calculations, then subtract
 * EPOCH_ADJUSTMENT to keep day numbers epoch-relative.
 * EPOCH_ADJUSTMENT = 1970/4 - 1970/100 + 1970/400 = 492 - 19 + 4 = 477 */
#define EPOCH_ADJUSTMENT 477

static sbyte4
DATETIME_calculateDayNumber( sbyte4 y, sbyte4 m, sbyte4 d)
{
    /* this routine converts a year, month, day into a day number */
    /* day number can just be used to compare quantities */
    /* http://alcor.concordia.ca/~gpkatch/ */
    sbyte4 cy; /* calendar year for correct leap year calculation */

    m = (m + 9)%12;         /* mar=0, feb=11 */
    y = y - m/10;           /* if Jan/Feb, year-- */
    /* FIX: Convert to calendar year for leap calculation since algorithm expects
     * year 0 to be a leap year, but our epoch (1970) is not a leap year */
    cy = y + 1970;
    return y*365 + cy/4 - cy/100 + cy/400 - EPOCH_ADJUSTMENT + (m*306 + 5)/10 + (d - 1);
}

/*-------------------------------------------------------------------------*/

static MSTATUS
DATETIME_calculateFromDayNumber(sbyte4 g, ubyte2 *pY, ubyte *pM, ubyte *pD)
{
    /* this routine converts  a day number into a year, month, day, hour, and seconds */
    /* http://alcor.concordia.ca/~gpkatch/ */
    sbyte4 y, cy, ddd, mi, mm, dd;

    y = (10000*g + 14780)/3652425;
    /* FIX: Convert to calendar year for leap calculation (same fix as forward function) */
    cy = y + 1970;
    ddd = g - (365*y + cy/4 - cy/100 + cy/400 - EPOCH_ADJUSTMENT);
    if (ddd < 0)
    {
        y = y - 1;
        cy = y + 1970;
        ddd = g - (365*y + cy/4 - cy/100 + cy/400 - EPOCH_ADJUSTMENT);
    }
    mi = (100*ddd + 52)/3060;
    mm = (mi + 2)%12 + 1;
    y = y + (mi + 2)/12;
    dd = ddd - (mi*306 + 5)/10 + 1;

    *pY = (ubyte2) y;
    *pM = (ubyte) mm;
    *pD = (ubyte) dd;
    return OK;
}

/*-------------------------------------------------------------------------*/

static MSTATUS
DATETIME_convertSecondsToTimeDate(sbyte4 seconds, TimeDate *pTD)
{
    sbyte4 left;
    pTD->m_second = seconds % 60;
    left = seconds / 60;
    pTD->m_minute = left % 60;
    left = left / 60 ;
    pTD->m_hour = left % 24;
    left = left / 24;
    DATETIME_calculateFromDayNumber(left, &pTD->m_year, &pTD->m_month, &pTD->m_day);
    return OK;
}

/*-------------------------------------------------------------------------*/

static sbyte4
DATETIME_calculateNumberSeconds( const TimeDate* pDT1)
{
    /* this routine converts DateTime into a number of seconds */
    return pDT1->m_hour * 60 * 60 +
        pDT1->m_minute * 60 +
        pDT1->m_second +
        DATETIME_calculateDayNumber( pDT1->m_year, pDT1->m_month, pDT1->m_day) * 24 * 60 * 60;
}

/*-------------------------------------------------------------------------*/

extern MSTATUS
DATETIME_getNewTime( const TimeDate* pDT1, sbyte4 secDiff, TimeDate *pDT2)
{
    sbyte4 seconds;

    seconds = DATETIME_calculateNumberSeconds(pDT1);
    DATETIME_convertSecondsToTimeDate(seconds+secDiff, pDT2);
    return OK;
}

/*-------------------------------------------------------------------------*/

extern MSTATUS
DATETIME_diffTime( const TimeDate* pDT1, const TimeDate* pDT2, sbyte4* pSecDiff)
{
    /* returns the difference in seconds between 2 DateTime structs */
    if ( !pDT1 || !pDT2 || !pSecDiff)
        return ERR_NULL_POINTER;

    *pSecDiff = DATETIME_calculateNumberSeconds( pDT1) -
                DATETIME_calculateNumberSeconds( pDT2);

    return OK;
}

/*------------------------------------------------------------------*/
/* convert to either UTCTIME or GENERALIZEDTIME as defined in rfc 3280 */
extern MSTATUS
DATETIME_convertToValidityString(const TimeDate *pTime, sbyte *pOutputTime)
{

    MSTATUS status = OK;
    ubyte4  temp;
    ubyte4 offset = 0;
    /* year */
    if (pTime->m_year < (2049 - 1970))
    {
        /* UTCTime */
        /* initialize */
        temp = pTime->m_year + 70;

        pOutputTime[0] = (ubyte)('0' + ((temp % 100) / 10));
        pOutputTime[1] = (ubyte)('0' + (temp % 10));

        offset = 2;
    }
    else
    {
        /* GeneralizedTime */
        temp = pTime->m_year + 1970;

        pOutputTime[0] = (ubyte)('0' + ((temp % 10000) / 1000));
        pOutputTime[1] = (ubyte)('0' + ((temp % 1000) / 100 ));
        pOutputTime[2] = (ubyte)('0' + ((temp % 100) / 10));
        pOutputTime[3] = (ubyte)('0' + (temp % 10));
        offset = 4;
    }

    temp = pTime->m_month;

    pOutputTime[offset] = (ubyte)('0' + (temp / 10));
    pOutputTime[offset+1] = (ubyte)('0' + (temp % 10));

    offset = offset + 2;

    temp = pTime->m_day;

    pOutputTime[offset] = (ubyte)('0' + (temp / 10));
    pOutputTime[offset + 1] = (ubyte)('0' + (temp % 10));

    offset = offset+ 2;

    temp = pTime->m_hour;

    pOutputTime[offset] = (ubyte)('0' + (temp / 10));
    pOutputTime[offset + 1] = (ubyte)('0' + (temp % 10));

    offset = offset + 2;

    temp = pTime->m_minute;

    pOutputTime[offset] = (ubyte)('0' + (temp / 10));
    pOutputTime[offset + 1] = (ubyte)('0' + (temp % 10));

    offset = offset + 2;

    temp = pTime->m_second;

    pOutputTime[offset] = (ubyte)('0' + (temp / 10));
    pOutputTime[offset + 1] = (ubyte)('0' + (temp % 10));

    pOutputTime[offset + 2] = (ubyte)('Z');

    pOutputTime[offset + 3] = '\0';

    return status;
}

/*------------------------------------------------------------------*/
/* convert to either UTCTIME or GENERALIZEDTIME as defined in rfc 3280 */

extern MSTATUS
DATETIME_convertFromValidityString2(const ubyte *pTimeString, ubyte4 timeStrLen, TimeDate *pTime)
{
    MSTATUS status = OK;
    ubyte4 offset = 0;
    ubyte4 year = 0;

    /* initialize */
    DIGI_MEMSET((ubyte*)pTime, 0x00, sizeof(TimeDate));

    /* year */
    if (timeStrLen == 13)
    {
        /* UTCTime */
        /* initialize */
        year = year + (pTimeString[0] - '0')*10;
        year = year + (pTimeString[1] - '0');
        year = year >= 70? year - 70 : year + 30;
        pTime->m_year = (ubyte2) year;
        offset = 2;
    } else
    {
        /* GeneralizedTime */
        year = year + (pTimeString[0] - '0')*1000;
        year = year + (pTimeString[1] - '0')*100;
        year = year + (pTimeString[2] - '0')*10;
        year = year + (pTimeString[3] - '0');
        year = year - 1970;
        pTime->m_year = (ubyte2) year;
        /* initialize */
        offset = 4;
    }

    /* month */
    pTime->m_month = (ubyte)(pTimeString[offset] - '0')*10;
    pTime->m_month = pTime->m_month + (ubyte)(pTimeString[offset+1] - '0');

    offset = offset + 2;

    /* day */
    pTime->m_day = (ubyte)(pTimeString[offset] - '0')*10;
    pTime->m_day = pTime->m_day + (ubyte)(pTimeString[offset+1] - '0');

    offset = offset+ 2;

    /* hour */
    pTime->m_hour = (ubyte)(pTimeString[offset] - '0')*10;
    pTime->m_hour = pTime->m_hour + (ubyte)(pTimeString[offset+1] - '0');

    offset = offset + 2;

    /* minute */

    pTime->m_minute = (ubyte)(pTimeString[offset] - '0')*10;
    pTime->m_minute = pTime->m_minute + (ubyte)(pTimeString[offset+1] - '0');

    offset = offset + 2;

    /* second */

    pTime->m_second = (ubyte)(pTimeString[offset] - '0')*10;
    pTime->m_second = pTime->m_second + (ubyte)(pTimeString[offset+1] - '0');

    return status;
}

extern MSTATUS
DATETIME_convertFromValidityString(const sbyte *pTimeString, TimeDate *pTime)
{
    ubyte4 timeStrLen;
    timeStrLen = DIGI_STRLEN(pTimeString);
    return DATETIME_convertFromValidityString2((ubyte *)pTimeString, timeStrLen, pTime);
}

#endif /* __DISABLE_DIGICERT_COMMON_DATE_TIME_UTILITY__ */
