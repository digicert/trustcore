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
