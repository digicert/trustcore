/*
 * merrors.c
 *
 * DigiCert Error Lookup
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

/*! Mocana error look up.
This file contains functions enabling Mocana error code look up.

! External Functions
This file contains the following public ($extern$) functions:
- $MERROR_lookUpErrorCode$

*/

#define __INTERNAL_MERRORS__

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"

/* setup for enum list */
#ifdef   __ERROR_LOOKUP_TABLE__
#undef   __ERROR_LOOKUP_TABLE__
#endif
#include "../common/merrors.h"

/* setup for lookup table */
#define  __ERROR_LOOKUP_TABLE__
#undef   __MERRORS_HEADER__
#undef   ERROR_DEF
#undef   ERROR_DEF_LAST

#include "../common/merrors.h"


/*------------------------------------------------------------------*/

#define NUM_ERROR_CODES     (sizeof(m_ErrorLookupTable) / sizeof(errDescr))

static const ubyte pNoErrorCodeMsg[] = "NO_ERROR_CODE_FOUND";

extern const ubyte *
MERROR_lookUpErrorCode(MSTATUS errorCode)
{
    ubyte* pErrorMesg = (ubyte *) pNoErrorCodeMsg;
    ubyte4 index;

    for (index = 0; index < NUM_ERROR_CODES; index++)
    {
        if (m_ErrorLookupTable[index].errorCode == errorCode)
        {
            pErrorMesg = m_ErrorLookupTable[index].pErrorMesg;
            break;
        }
    }

    return pErrorMesg;
}

