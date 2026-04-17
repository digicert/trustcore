/*
 * datetime.h
 *
 * Date Time routines
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


/*------------------------------------------------------------------*/

#ifndef __DATETIME_HEADER__
#define __DATETIME_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* caculate the number of seconds diff between two TimeDates */
MOC_EXTERN MSTATUS
DATETIME_diffTime( const TimeDate* pDT1, const TimeDate* pDT2, sbyte4* pSecDiff);

/* caculate a new TimeDate by offseting the first TimeDate by a seconds diff */
MOC_EXTERN MSTATUS
DATETIME_getNewTime( const TimeDate* pDT1, sbyte4 secDiff, TimeDate *pDT2);

/* Return a NULL terminated string representing the Validity in a X.509 certificate , as defined in RFC3280.
 * The return string format will be either UTCTIME or GENERALIZEDTIME depending on the time.
 */
MOC_EXTERN MSTATUS
DATETIME_convertToValidityString(const TimeDate *pTime, sbyte *pTimeString);

/* Convert a NULL terminated string representing the Validity time, as defined in RFC3280,
 * to a TimeDate */
MOC_EXTERN MSTATUS
DATETIME_convertFromValidityString(const sbyte *pTimeString, TimeDate *pTime);

MOC_EXTERN MSTATUS
DATETIME_convertFromValidityString2(const ubyte *pTimeString, ubyte4 timeStrLen, TimeDate *pTime);


#ifdef __cplusplus
}
#endif

#endif /* __MTCP_HEADER__ */
