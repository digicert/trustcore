/*
 * renesas_sce.h
 *
 * Renaissance Hardware Acceleration
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/mdefs.h"
#include "common/merrors.h"
#include "crypto/sha1.h"
#include "r_crypto_api.h"
#include "r_hash_api.h"
#include "crypto/sha256.h"


#ifndef RENESAS_SCE_H
#define RENESAS_SCE_H

const hash_api_t g_hash_on_sce;


hash_ctrl_t      sha1_ctrl;
hash_cfg_t       sha1_cfg;
uint32_t         sha1InitialValue[5];

hash_ctrl_t      sha256_ctrl;
hash_cfg_t      sha256_cfg;


void byteArrayToWordArray(const ubyte* source, ubyte4* dest, ubyte4 byteCount, ubyte* pRetPaddedAdded);
void ssp_crypto_initialize(void);
extern sbyte4 SYNERGY_init(void);
extern sbyte4 SYNERGY_uninit(void);
extern sbyte4 SYNERGY_openChannel(enum moduleNames moduleId, hwAccelDescr *pHwAccelCookie);
extern sbyte4 SYNERGY_closeChannel(enum moduleNames moduleId, hwAccelDescr *pHwAccelCookie);

#endif
