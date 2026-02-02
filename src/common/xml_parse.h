/*
 * xml_parse.h
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

#define MAX_TAG_NAME 32;

MOC_EXTERN MSTATUS findTagName(ubyte * pBuff, sbyte4 maxBytesToParse, sbyte4 * bytesParsed, ubyte * tagContents );
MOC_EXTERN MSTATUS findTagValue(ubyte * pBuff, sbyte4 maxBytesToParse, sbyte4 * bytesParsed, ubyte * tagValue );