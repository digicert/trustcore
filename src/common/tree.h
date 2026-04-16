/*
 * tree.h
 *
 * Mocana ASN1 Tree Abstraction Layer
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

#ifndef __TREE_H__
#define __TREE_H__

#ifdef __cplusplus
extern "C" {
#endif
    
struct TreeItem;
/* this is a destructor function that will be called
when the tree item is deleted */
typedef void (*TreeItemDtor)(struct TreeItem*);

typedef struct TreeItem
{
    struct TreeItem* m_pParent;
    struct TreeItem* m_pFirstChild;
    struct TreeItem* m_pNextSibling;
    TreeItemDtor            m_dtorFun;
} TreeItem;


/*------------------------------------------------------------------*/

MOC_EXTERN TreeItem*    TREE_MakeNewTreeItem(sbyte4 size);
MOC_EXTERN MSTATUS      TREE_AppendChild( TreeItem* pParent, TreeItem* pChild);
MOC_EXTERN MSTATUS      TREE_DeleteTreeItem( TreeItem* pTreeItem);
MOC_EXTERN MSTATUS      TREE_DeleteChildren( TreeItem* pTreeItem);
MOC_EXTERN TreeItem*    TREE_GetParent( TreeItem* pTreeItem);
MOC_EXTERN TreeItem*    TREE_GetFirstChild( TreeItem* pTreeItem);
MOC_EXTERN TreeItem*    TREE_GetNextSibling(TreeItem* pTreeItem);
MOC_EXTERN sbyte4       TREE_GetTreeItemLevel(TreeItem* pTreeItem);

/* the VisitTreeFunc should return FALSE to stop the visit */
typedef sbyte4 (*VisitTreeFunc)(TreeItem* treeItem, void* arg);

/* VisitTree returns the tree item on which the visit was stopped if the visit was interrupted by the VisitTreeFunc */
MOC_EXTERN TreeItem*    TREE_VisitTree(TreeItem* start, VisitTreeFunc visitTreeFunc, void* arg);

#ifdef __cplusplus
}
#endif    
    
#endif
