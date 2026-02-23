/* ------------------------------------------------------------ *
 * file:        common.h	                                *
 * author:      05/10/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#ifndef COMMON_H
#define COMMON_H

#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "logger.h"

#define TEST_CATEGORIES              4

#define MAX_URL_LENGTH               2083
#define MAX_PATH_LENGTH              4096

#define MIN_PORT                     0
#define MAX_PORT                     65535

#define MAX_SESSION                  1

#define EXIT_PASS                    0
#define EXIT_FAIL                    -1

#define MAX_GROUPSIZE                50
#define DEFAULT_TEST_CASE_CONF_FILE  "./conf/test_case.conf"
#define CLIENT_CONFIG                "./conf/client.conf"
#define SERVER_CONFIG                "./conf/server.conf"

struct TestCases{
   int initCases[MAX_GROUPSIZE];
   int handshakeCases[MAX_GROUPSIZE];
   int data_exchCases[MAX_GROUPSIZE];
   int cleanupCases[MAX_GROUPSIZE];
};

struct Config{
   int  port;
   char dest_url[MAX_URL_LENGTH];
   char certificate_file[MAX_PATH_LENGTH];
   char private_key_file[MAX_PATH_LENGTH];
   int  max_session_reuse;
   struct TestCases testCases;
};

/*Data initialization functions*/
int CheckTestCase(int[], int);
int InitializeTestConfiguration(struct Config**, char*, char*);
int InitializeConfiguration(struct Config**, char*);

/*Group APIs list for testing*/

/*Common APIs*/
#define SSL_CTX_SET_OPTIONS     1021
#define SSL_CTX_CLEAR_OPTIONS   1022
#define SSL_CTX_GET_OPTIONS     1023

/*Client Initialization Group APIs codes*/
#define CLIENT_INIT             100
#define SSLV23_CLIENT_METHOD    100
#define SSLV3_CLIENT_METHOD     1011
#define TLSV1_CLIENT_METHOD     1012
#define TLSV1_1_CLIENT_METHOD   1013
#define TLSV1_2_CLIENT_METHOD   1014
#define SSL_SET_SESSION         1021

/*Client Handshake Group APIs codes*/
#define CLIENT_HANDSHAKE        200
#define SSL_GET1_SESSION        2021

/*Client Data-exchange Group APIs codes*/
#define CLIENT_DATA_EXCH        300
#define SSL_WRITE               3011
#define SSL_READ                3012

/*Client Cleanup Group APIs codes*/
#define CLIENT_CLEANUP          400

/*Server Initialization Group APIs codes*/
#define SERVER_INIT             100
#define SSLV23_SERVER_METHOD    100
#define SSLV3_SERVER_METHOD     1011
#define TLSV1_SERVER_METHOD     1012
#define TLSV1_1_SERVER_METHOD   1013
#define TLSV1_2_SERVER_METHOD   1014

/*Server Handshake Group APIs codes*/
#define SERVER_HANDSHAKE        200

/*Server Data-exchange Group APIs codes*/
#define SERVER_DATA_EXCH        300

/*Server Cleanup Group APIs codes*/
#define SERVER_CLEANUP          400


/*Common API Testing functions*/
int CheckSSLCTXSetOptions(SSL_CTX*);
int CheckSSLCTXGetOptions(SSL_CTX*, long*);
int CheckSSLCTXClearOptions(SSL_CTX*);
#endif

