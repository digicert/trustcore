/*
 * server.h
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
 * file:        server.h	                                	*
 * author:      05/11/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#ifndef SERVER_H
#define SERVER_H 

#include "common.h"

int create_socket_server     (int);
int Server_Init_Test         (struct Config*);
int Server_Handshake_Test    (struct Config*, SSL_CTX*, int);
int Server_Data_Exchange_Test(struct Config*, SSL*);
int Server_CleanUp_Test      (struct Config*, int);

#endif
