/*
 * client.h
 *
 * Header file
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
 *
 */

/* ------------------------------------------------------------ *
 * file:        client.h  	     	                            *
 * author:      05/03/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#ifndef CLIENT_H
#define CLIENT_H 

#include "common.h"

int create_socket            (char*, int);
int Client_Init_Test         (struct Config*);
int Client_Handshake_Test    (struct Config*, SSL_CTX*);
int Client_Data_Exchange_Test(struct Config*, SSL*, int, int);
int Client_CleanUp_Test      (struct Config*, SSL*, int);

#endif
