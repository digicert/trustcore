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
