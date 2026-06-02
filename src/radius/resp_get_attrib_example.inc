/**
 * @file  resp_get_attrib_example.inc
 * @brief RADIUS response attribute retrieval example code
 *
 * @details    Example code for getting attributes from RADIUS responses
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */

\example
/* This is a generic RADIUS_ResponseGetAttribute* example
\endds_doc
while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
{
    // demonstrate RADIUS_responseGetAttributeAsXXXX
    if (sizeof(ubyte4) == len)
    {
        if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
            printf("Attribute as ubyte4 hex: %x\n", ubyte4Value);
    }
    else if (RADIUS_ATTR_VENDOR_SPECIFIC == type)
    {
        if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
        {
            printf("Vendor-Specific attribute\n");
            printf("Vendor ID: %d\n", vendorID);

            if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
            {
                printf("Attribute has sub-attributes\n");
                done = FALSE;
                j = 0;

                while (!done)
                {
                    if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                    {
                        printf("    Sub-Attribute: #%d\n", j);
                        printf("             Type: %d\n", (int)subType);
                        printf("            Value: ");
                        radius_printChars(pSubData, subLength);
                        printf("\n");
                        j++;
                    }
                    else
                    {
                        done = TRUE;
                    }
                }
            }
            else
            {
                printf("Attribute has no sub-attributes\n");
            }
        }
    }
    else
    {
        if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
            printf("Attribute as string: %s\n", pStringValue);

        RADIUS_responseFreeString(&pStringValue); // REMEMBER TO DO THIS !!!
    }
    i++;
}

\endexample