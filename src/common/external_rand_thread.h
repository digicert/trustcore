/*
 * external_rand_thread.h
 *
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
#ifndef EXTERNAL_RAND_THREAD_H
#define EXTERNAL_RAND_THREAD_H
MOC_EXTERN MSTATUS DIGICERT_waitForExternalEntropy (void);
MOC_EXTERN MSTATUS DIGICERT_cancelExternalEntropy (void);
MOC_EXTERN MSTATUS DIGICERT_addExternalEntropyThread (void);
MOC_EXTERN MSTATUS DIGICERT_addExternalEntropy (int async);
MOC_EXTERN MSTATUS DIGICERT_addExternalEntropyThreadWait (void);
#endif
