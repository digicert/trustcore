/*
 * merrors.c
 *
 * Mocana Error Lookup
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

