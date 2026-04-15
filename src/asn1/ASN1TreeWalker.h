/*
 * ASN1TreeWalker.h
 *
 * ASN1 Parse Tree Walker
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

#ifndef __ASN1TREEWALKER_HEADER__
#define __ASN1TREEWALKER_HEADER__

#include "../asn1/parseasn1.h"
#include "../common/merrors.h"

/*------------------------------------------------------------------*/

/* Walker instructions codes */
#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    Complete,           /* always use this to indicate end of instructions */
    GoFirstChild,       /* unused, unused */
    GoNextSibling,      /* unused, unused */
    GoParent,           /* unused, unused */
    GoToTag,            /* tag, unused */
    VerifyType,         /* type, unused */
    VerifyTag,          /* tag, unused */
    VerifyOID,          /* unused, &oid */
    VerifyInteger,      /* number, unused */
    GoChildWithTag,     /* tag, unused */
    GoChildWithOID,     /* unused, &oid */
    GoNthChild,         /* child #, unused */
    GoFirstChildBER     /* unused, unused */
} E_WalkerInstructions;

typedef struct WalkerStep
{
    E_WalkerInstructions    instruction;
    sbyte4                  extra1; /* tag or type or length or number */
    const ubyte*            extra2; /* oid (first byte is length)*/
} WalkerStep;

/* exported routines */

MOC_EXTERN MSTATUS ASN1_WalkTree(ASN1_ITEM* pStart,
                             CStream s,
                             const WalkerStep* pSteps,
                             ASN1_ITEM** pFound);

#ifdef __cplusplus
}
#endif
#endif  /*#ifndef __ASN1TREEWALKER_HEADER__ */
