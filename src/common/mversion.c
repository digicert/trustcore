/*
 * mversion.c
 *
 * Mocana Initialization
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
/**
@file       mversion.c
@brief      Mocana SoT Platform version read function.
@details    This file contains functions to be used to read the version of the binary library.

@since 1.41
@version 3.06 and later

@filedoc    mversion.c
*/

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/mversion.h"


/*------------------------------------------------------------------*/


/*------------------------------------------------------------------*/
/**
@brief      Return the version string as requested by the \p type parameter.

@ingroup    common_functions

@since 5.4.2
@version 5.4.2 and later

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@param type         The enum value describing the requested version type.
@param pRetBuffer   Pointer to memory, that will be overwritten by this method.
                    The character array stored in the memory is the version
                    string. The string will be terminated by '\0'.
@param retBufLength The number of characters that can be stored in the above 
                    area. This method return an error code if the buffer is not
                    large enough.

@funcdoc ssl.c
 */
extern sbyte4
DIGICERT_readVersion(sbyte4 type, ubyte* pRetBuffer, ubyte4 retBufLength)
{
	MSTATUS status = OK;
	ubyte4 total = 0;
	char add = FALSE;

#ifndef __DIGICERT_DSF_BUILD_STR__
#define __DIGICERT_DSF_BUILD_STR__ "(unknown)"
#endif

#ifndef __DIGICERT_DSF_BUILDTIME_STR__
#define __DIGICERT_DSF_BUILDTIME_STR__ "(unknown)"
#endif


	if ((type & VT_MAIN) != 0)
	{
		total = DIGI_STRLEN((sbyte*)__DIGICERT_DSF_VERSION_STR__) + 1;
	}

	if ((type & VT_BUILD) != 0)
	{
		total += DIGI_STRLEN((sbyte*)__DIGICERT_DSF_BUILD_STR__) + 1;
	}

	if ((type & VT_TIMESTAMP) != 0)
	{
		total += DIGI_STRLEN((sbyte*)__DIGICERT_DSF_BUILDTIME_STR__) + 1;
	}

	if (total > 0)
	{
		if (total >= retBufLength)
		{
			return ERR_BUFFER_OVERFLOW;
		}


		if ((type & VT_MAIN) != 0)
		{
			DIGI_STRCBCPY((sbyte*)pRetBuffer, total,(sbyte*)__DIGICERT_DSF_VERSION_STR__);
			add = TRUE;
		}

		if ((type & VT_BUILD) != 0)
		{
			if (add)
			{
				DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)" ");
				DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)__DIGICERT_DSF_BUILD_STR__);
			}
			else
			{
				DIGI_STRCBCPY((sbyte*)pRetBuffer, total, (sbyte*)__DIGICERT_DSF_BUILD_STR__);
			}
			add = TRUE;
		}

		if ((type & VT_TIMESTAMP) != 0)
		{
			if (add)
			{
				DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)" ");
				DIGI_STRCAT((sbyte*)pRetBuffer, (sbyte*)__DIGICERT_DSF_BUILDTIME_STR__);
			}
			else
			{
				DIGI_STRCBCPY((sbyte*)pRetBuffer, total, (sbyte*)__DIGICERT_DSF_BUILDTIME_STR__);
			}
			add = TRUE;
		}
	}
	else
	{
		/* No good type parameter */
		return ERR_INVALID_ARG;
	}

	return status;
}

/*------------------------------------------------------------------*/

