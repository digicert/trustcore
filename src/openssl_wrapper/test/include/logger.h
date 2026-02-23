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
