/* ------------------------------------------------------------ *
 * file:        common.c                                        *
 * purpose:     Common APIs definiions for Client/Server Testing*
 * author:      05/19/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#include "common.h"

int CheckTestCase(int testCaseList[], int key)
{
    int status = EXIT_FAIL;
    int index=0;
    for(index; index<=MAX_GROUPSIZE; index++)
    {
      if(testCaseList[index]==key)
      {
         status = EXIT_PASS;
         break;
      }
    }
    return status;
}

int InitializeTestConfiguration(struct Config **config, char* mode, char *fileName)
{
    int category;
    int init=0, hds=0, dex=0, clp=0;
    int status = EXIT_PASS;
    char line[100];
    char *key, *value;
    FILE* testfp = NULL;
    char* testCategories[]={"client_init",      "client_handshake",
                            "client_data_exch", "client_cleanup",
                            "server_init",      "server_handshake",
                            "server_data_exch", "server_cleanup"};
    int count;
    category = strcmp(mode,"client")==0 ? 0:4;

    testfp=fopen(fileName,"r");
    if(testfp!=NULL)
    {
        while(!feof(testfp))
        {
            if (fgets(line,sizeof(line),testfp)==NULL)
            {
                break;
            }
            else
            {
                key = strtok(line, "=");
                if (!strcmp(key,"max_session_reuse"))
                {
                    value = strtok(NULL, "=");
                    value = strtok(value, "\n");
                    if (atoi(value)<=0)
                    {
                        LOG_PRINT("ERROR: Max session value should be "
                                  "greator then 0");
                        status=EXIT_FAIL;
                        goto end;
                    }
                    else
                    {
                        (*config)->max_session_reuse = atoi(value);
                    }
                }
                else
                {
                    (*config)->max_session_reuse = MAX_SESSION;
                }

                if(strcmp(key,testCategories[category])==0)
                {
                   value = strtok(NULL, "=");
                   value = strtok(value, ",");
                   while(value!=NULL)
                   {
                       if(EXIT_PASS!=CheckTestCase(
                                (*config)->testCases.initCases, atoi(value)))
                       {
                          (*config)->testCases.initCases[init]=atoi(value);
                       }
                       value = strtok(NULL, ",");
                       init++;
                   }
                }
                if(strcmp(key,testCategories[category+1])==0)
                {
                    value = strtok(NULL, "=");
                    value = strtok(value, ",");
                    while(value!=NULL)
                    {
                        if(EXIT_PASS!=CheckTestCase(
                             (*config)->testCases.handshakeCases, atoi(value)))
                        {
                           (*config)->testCases.handshakeCases[hds]=atoi(value);
                        }
                        value = strtok(NULL, ",");
                        hds++;
                    }
                }
                if(strcmp(key,testCategories[category+2])==0)
                {
                    value = strtok(NULL, "=");
                    value = strtok(value, ",");
                    while(value!=NULL)
                    {
                        if(EXIT_PASS!=CheckTestCase(
                             (*config)->testCases.data_exchCases, atoi(value)))
                        {
                           (*config)->testCases.data_exchCases[dex]=atoi(value);
                        }
                        value = strtok(NULL, ",");
                        dex++;
                    }
                }
                if(strcmp(key,testCategories[category+3])==0)
                {
                    value = strtok(NULL, "=");
                    value = strtok(value, ",");
                    while(value!=NULL)
                    {
                        if(EXIT_PASS!=CheckTestCase(
                             (*config)->testCases.cleanupCases, atoi(value)))
                        {
                           (*config)->testCases.cleanupCases[clp]=atoi(value);
                        }
                        value = strtok(NULL, ",");
                        clp++;
                    }
                }
            }
        }
    }
    else
    {
        fprintf(stderr, "Can't open Test case file %s !\n", fileName);
        status = EXIT_FAIL;
    }

end:
    fclose(testfp);
    return status;
}

int InitializeConfiguration(struct Config **config, char* mode)
{
    int count     = 0;
    int i         = 0;
    FILE *fp      = NULL;
    FILE *testfp  = NULL;
    int status    = EXIT_PASS;
    char line[100];
    char *key, *value;
    if (strcmp(mode,"client")==0)
    {
        fp = fopen(CLIENT_CONFIG, "r");
        if(fp!=NULL)
        {
            while(!feof(fp))
            {
                if (fgets(line,sizeof(line),fp)==NULL)
                {
                    break;
                }
                else
                {
                    key=strtok(line, "=");
                    if (!strcmp(key,"dest_url"))
                    {
                        value = strtok(NULL, "=");
                        value = strtok(value, "\n");
                        if (strlen(value)>MAX_URL_LENGTH)
                        {
                            LOG_PRINT("ERROR: Provided URL length should be "
                                    "less than %s characters", MAX_URL_LENGTH);
                            status = EXIT_FAIL;
                            goto end;
                        }
                        strcpy((*config)->dest_url, value);
                    }
                    if (!strcmp(key,"port"))
                    {
                        value = strtok(NULL, "=");
                        value = strtok(value, "\n");
                        if ((atoi(value)<MIN_PORT)
                         && (atoi(value)>MAX_PORT))
                        {
                            LOG_PRINT("ERROR: Provided Port should be in reange"
                                      " between %d and %d.", MIN_PORT, MAX_PORT);
                            status = EXIT_FAIL;
                            goto end;
                        }
                        (*config)->port = atoi(value);
                    }
                    strcpy((*config)->certificate_file,"\0");
                    strcpy((*config)->private_key_file,"\0");
                }
            }
        }
        else
        {
            fprintf(stderr, "Can't open Client Config File %s !\n", CLIENT_CONFIG);
            status = EXIT_FAIL;
            goto end;
        }
    }
    if (strcmp(mode,"server")==0)
    {
        fp=fopen(SERVER_CONFIG,"r");
        if (fp!=NULL)
        {
            for(count=0;count<3;count++)
            {
                if (fgets(line,sizeof(line),fp)==NULL)
                {
                    break;
                }
                else
                {
                    strcpy((*config)->dest_url,"\0");
                    key=strtok(line, "=");
                    if (!strcmp(key,"port"))
                    {
                        value = strtok(NULL, "=");
                        value = strtok(value, "\n");
                        if ((atoi(value)<MIN_PORT)
                         && (atoi(value)>MAX_PORT))
                        {
                           LOG_PRINT("ERROR: Provided Port should be in reange"
                                     " between %d and %d.", MIN_PORT, MAX_PORT);
                           status = EXIT_FAIL;
                           goto end;
                        }
                        (*config)->port = atoi(value);
                    }
                    if (!strcmp(key,"certificate_file"))
                    {
                        value = strtok(NULL, "=");
                        value = strtok(value, "\n");
                        if (strlen(value)>MAX_PATH_LENGTH)
                        {
                            LOG_PRINT("ERROR: Provided certificate file path "
                                      "length should be less than %s "
                                      "characters", MAX_PATH_LENGTH);
                            status = EXIT_FAIL;
                            goto end;
                        }
                        strcpy((*config)->certificate_file, value);
                    }
                    if (!strcmp(key,"privateKey_file"))
                    {
                        value = strtok(NULL, "=");
                        value = strtok(value, "\n");
                        if (strlen(value)>MAX_PATH_LENGTH)
                        {
                            LOG_PRINT("ERROR: Provided private key file path "
                                      "length should be less than %s "
                                      "characters", MAX_PATH_LENGTH);
                            status = EXIT_FAIL;
                            goto end;
                        }
                        strcpy((*config)->private_key_file, value);
                    }
                }
            }
        }
        else
        {
            fprintf(stderr, "Can't open Client Config File %s !\n", SERVER_CONFIG);
            status = EXIT_FAIL;
            goto end;
        }
    }

end:
    fclose(fp);
    return status;
}


//TBD: Options "SSL_OP_NO_SSLv2" is fixed for testing
//Impilmentaion will change for other SSL options
/*Setting SSL CONTEXT Options*/
int CheckSSLCTXSetOptions(SSL_CTX* ctx)
{
    int status = EXIT_PASS;
    int ret;
    printf("Setting SSL CTX options\n");
    ret = SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if((ctx == NULL && ret<=0) ||
       (ctx == NULL && ret >0) ||
       (ctx != NULL && ret<=0))
    {
        LOG_PRINT("Unable to set new SSL context options.");
        check_ssl_api_error("SSL_CTX_set_options");
        status = EXIT_FAIL;
        goto end;
    }
    else if (ctx != NULL && ret >0)
    {
        LOG_PRINT("SSL_CTX_set_options::PASSED");
    }

end:
    return status;
}

/*Get SSL Context Option*/
int CheckSSLCTXGetOptions(SSL_CTX* ctx, long* sslctxOptions)
{
    int status = EXIT_PASS;
    printf("Getting SSL CTX options\n");
    *sslctxOptions = SSL_CTX_get_options(ctx);
    if (*sslctxOptions!=0)
    {
        printf("SSL CTX options value is: %ld\n", *sslctxOptions);
        LOG_PRINT("SSL_CTX_get_options::PASSED");
    }
    else
    {
        LOG_PRINT("Unable to get SSL context options.");
        check_ssl_api_error("SSL_CTX_get_options");
        status = EXIT_FAIL;
        goto end;
    }

end:
    return status;
} 

/*Clear SSL context value*/
int CheckSSLCTXClearOptions(SSL_CTX* ctx)
{
    int status = EXIT_PASS;
    int ret;
    printf("Clear SSL CTX options\n");
    ret = SSL_CTX_clear_options(ctx, SSL_OP_NO_SSLv2);
    if((ctx == NULL && ret<=0) ||
       (ctx == NULL && ret >0) ||
       (ctx != NULL && ret<=0))
    {
        LOG_PRINT("Unable to clear SSL context options.");
        check_ssl_api_error("SSL_CTX_clear_options");
        status = EXIT_FAIL;
        goto end;
    }
    else if (ctx != NULL && ret >0)
    {
             LOG_PRINT("SSL_CTX_clear_options::PASSED");
    }
end:
    return status;
}
