/*
 * xml_parse.c
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

#if ( defined (__ENABLE_DIGICERT_XML_PARSE__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/int64.h"
#include "../common/sizedbuffer.h"
#include "../common/xml_parse.h"



#include <string.h>
#include <stdio.h>

/* given input of "      <tag>" return "tag\0" */

extern MSTATUS findTagName(ubyte * pBuff, sbyte4 maxBytesToParse, sbyte4 * bytesParsed, ubyte * tagContents )
{
    MSTATUS status = OK;
    sbyte4 beginIndex = 0;
    sbyte4 endIndex = 0;
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '<'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_BEGIN_TAG;
        goto exit;
        
    }
    
    beginIndex = *bytesParsed + 1;
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '>'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_END_TAG;
        goto exit;

    }
    
    endIndex = *bytesParsed ;
    
    *bytesParsed++;
    
    DIGI_MEMCPY(tagContents, pBuff+beginIndex, endIndex - beginIndex);
    
    DIGI_MEMCPY(tagContents+(endIndex - beginIndex), "\0", 2);

exit:
    return status;
    
}

extern MSTATUS findTagValue(ubyte * pBuff, sbyte4 maxBytesToParse, sbyte4 * bytesParsed, ubyte * tagValue )
{
    MSTATUS status = OK;
    sbyte4 beginIndex = 0;
    sbyte4 endIndex = 0;
    
    sbyte4 depth = 0;
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '<'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_BEGIN_TAG;
        goto exit;
        
    }
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '>'); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_NO_END_TAG;
        goto exit;
    }
    
    (*bytesParsed)++;
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) == ' '); (*bytesParsed)++);
    
    if (*bytesParsed == maxBytesToParse) {
        
        status = ERR_XML_PARSE_VALUE_NOT_FOUND;
        goto exit;
    }
    
    if ( *(pBuff+*bytesParsed) == '<' && *(pBuff+*bytesParsed+1) == '/')
        return ERR_XML_PARSE_END_TAG_TOO_EARLY;
    
    beginIndex = *bytesParsed;
    
    (*bytesParsed)++;
    
    for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '<'); (*bytesParsed)++);
    
    if (*bytesParsed >= maxBytesToParse) {
        
        status = ERR_XML_PARSE_VALUE_NOT_FOUND;
        goto exit;
        
    }
    
    endIndex = *bytesParsed;
    
    *bytesParsed++;
    
    DIGI_MEMCPY(tagValue, pBuff+beginIndex, endIndex - beginIndex);
    
    DIGI_MEMCPY(tagValue+(endIndex - beginIndex), "\0", 2);
    
#if 0
    /* come back to this later.  not necessary for now */
    /* handle case where value is after series of tags */
    if ( *(pBuff+*bytesParsed) == '<' )
    {
        depth++;
        /* handle case where value is after series of tags */
        
        while( depth != 0)
        {
            
            for(; (*bytesParsed < maxBytesToParse && *(pBuff+*bytesParsed) != '>'); (*bytesParsed)++);
            
            if (*bytesParsed == maxBytesToParse) {
                
                status = ERR_XML_PARSE_VALUE_NOT_FOUND;
                goto exit;
                            }
            
        }
        
    }
#endif

exit:
    return status;
    
}



#endif
