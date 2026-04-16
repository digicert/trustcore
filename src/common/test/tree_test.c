/*
 * tree_test.c
 *
 * unit test for tree.c
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

#include "../tree.c"
#include "../../../unit_tests/unittest.h"


int tree_test_1(void)
{
  int i;
    int errors = 0;
    TreeItem *pChild = NULL;
    TreeItem *pParent = NULL;
    TreeItem *pRoot = TREE_MakeNewTreeItem(32);

    if (NULL == pRoot)
    {
        errors++;
        return errors;
    }
   
    pParent = pRoot;

    for (i=0; i<1000;i++)
    {
        pChild = TREE_MakeNewTreeItem(32);
        if (NULL != pChild)
        {
          errors += UNITTEST_STATUS(1, TREE_AppendChild(pParent, pChild));
          pParent = pChild;
        }
    }

    errors += UNITTEST_STATUS(1, TREE_DeleteTreeItem(pRoot));

     return errors;
}
