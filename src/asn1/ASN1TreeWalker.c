/*
 * ASN1TreeWalker.c
 *
 * ASN1 Tree Walker
 *
 * This is used to navigate ASN1 Parse Trees
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

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../crypto/rsa.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"


/*--------------------------------------------------------------------------*/

extern MSTATUS
ASN1_WalkTree(ASN1_ITEM* pCurrent, CStream s,
              const WalkerStep* pSteps, ASN1_ITEM** pFound)
{
    MSTATUS status = OK;

    if (0 == pCurrent || 0 == pSteps || 0 == pFound)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFound = NULL;

    while (Complete != pSteps->instruction)
    {
        switch (pSteps->instruction)
        {
            case GoFirstChild:
            {
                pCurrent = ASN1_FIRST_CHILD(pCurrent);

                break;
            }

            case GoNextSibling:
            {
                pCurrent = ASN1_NEXT_SIBLING(pCurrent);

                break;
            }

            case GoParent:
            {
                pCurrent = (ASN1_ITEM*) pCurrent->treeItem.m_pParent;

                break;
            }

            case VerifyType:
            {
                if (OK != ASN1_VerifyType(pCurrent, pSteps->extra1))
                {
                    status = ERR_WALKER_VERIFY_FAILED;
                    goto exit;
                }

                break;
            }

            case VerifyTag:
            {
                if (OK != ASN1_VerifyTag(pCurrent, pSteps->extra1) )
                {
                    status = ERR_WALKER_VERIFY_FAILED;
                    goto exit;
                }

                break;
            }

            case VerifyOID:
            {
                if (0 == pSteps->extra2)
                {
                    status = ERR_WALKER_INVALID_INSTRUCTION;
                    goto exit;
                }

                if (OK != ASN1_VerifyOID(pCurrent, s, pSteps->extra2))
                {
                    status = ERR_WALKER_VERIFY_FAILED;
                    goto exit;
                }

                break;
            }

            case VerifyInteger:
            {
                if (OK != ASN1_VerifyInteger(pCurrent, pSteps->extra1))
                {
                    status = ERR_WALKER_VERIFY_FAILED;
                    goto exit;
                }

                break;
            }

            case GoChildWithTag:
            {
                if (OK > (status = ASN1_GetChildWithTag(pCurrent, pSteps->extra1, &pCurrent)))
                    goto exit;

                break;
            }

            case GoToTag:
            {
                if (OK > (status = ASN1_GoToTag(pCurrent, pSteps->extra1, &pCurrent)))
                    goto exit;

                break;
            }

            case GoChildWithOID:
            {
                if (0 == pSteps->extra2)
                {
                    status = ERR_WALKER_INVALID_INSTRUCTION;
                    goto exit;
                }

                if (OK > (status = ASN1_GetChildWithOID(pCurrent, s, pSteps->extra2, &pCurrent)))
                    goto exit;

                break;
            }

            case GoNthChild:
            {
                if (OK > (status = ASN1_GetNthChild(pCurrent, pSteps->extra1, &pCurrent)))
                    goto exit;

                break;
            }

            case GoFirstChildBER:
            {
                /* if pCurrent is an OCTESTSTRING and is constructed go to its child */
                pCurrent = ASN1_FIRST_CHILD(pCurrent);
                if ((pCurrent->id & CONSTRUCTED) && (OK == ASN1_VerifyType( pCurrent, OCTETSTRING)))
                {
                    pCurrent = ASN1_FIRST_CHILD(pCurrent);
                }
                break;
            }

            default:
            {
                status = ERR_WALKER_UNKNOWN_INSTRUCTION;
                goto exit;
            }

        } /* switch */

        /* check we are still on the tree */
        if (0 == pCurrent)
        {
            status = ERR_WALKER_OUT_OF_TREE;
            goto exit;
        }

        pSteps++; /* next instruction */

    } /* while (Complete != pSteps->instruction ) */

    *pFound = pCurrent;

exit:
    return status;
}


#endif /* __DISABLE_DIGICERT_CERTIFICATE_PARSING__ */
