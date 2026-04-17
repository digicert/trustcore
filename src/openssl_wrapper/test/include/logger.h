/*
 * logger.h
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
 * file:        logger.h                                        *
 * author:      05/22/2017 rdwivedi                             *
 * ------------------------------------------------------------ */


#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

#define LOGGER_FILE_NAME "testharness.log"


char* ossl_err_as_string(void);
void log_print(char* filename, int line,const char* functionName, char *fmt,...);
void check_ssl_api_error(char *);

#define LOG_PRINT(...) log_print(__FILE__, __LINE__, __func__, __VA_ARGS__ )

#endif
