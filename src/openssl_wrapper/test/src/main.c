/* ------------------------------------------------------------ *
 * file:        main.c                                          *
 * purpose:     Main Entry point for TestHarness                * 
 * author:      05/03/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#include "main.h"

void displayUsageHelp()
{
    printf("Error   : Few Arguments\n\n");
    printf("Command help:\n");

    printf("With Default test case configuration file :\n");
    printf("          ./openssl_testharness <mode:(server/client)>\n\n");

    printf("With Custom test case configuration file :\n");
    printf("          ./openssl_testharness -f <mode:(server/client)> <filename>\n");
}

int startTest(char* fileName, char* mode)
{
    int count;
    int status = EXIT_PASS;
    struct Config *config = (struct Config*)malloc(sizeof(struct Config));
    LOG_PRINT("#############################################################");
    if (EXIT_PASS!=(status=InitializeConfiguration(&config, mode)))
    {
        printf("Failed to Initialize the %s configuration.\n", mode);
        goto end;
    }
  
    if (EXIT_PASS!=(status=InitializeTestConfiguration(&config, mode, fileName)))
    {
        LOG_PRINT("Failed to initialize test configuration file.");
        LOG_PRINT("Please review test configuration file %s", fileName);
        goto end;
    }

    LOG_PRINT("OpenSSL Testharness Started");
    if (strcmp(mode,"client")==0)
    {
        if (EXIT_PASS!=(status=CheckTestCase(config->testCases.initCases, 
                                             CLIENT_INIT)))
        {
            printf("Basic test group id %d for Client Initialization is "
                   "Not Found. Test aborted\n", CLIENT_INIT);
            goto end;
        }
        else
        {
            printf("Client testing started\n");
            if (EXIT_PASS!=(status=Client_Init_Test(config)))
            {
                printf("Client TCP/IP connection Failed. Please refer logs.\n");
                goto end;
            }
            printf("Client testing ended\n");
        }
    }
    if (strcmp(mode,"server")==0)
    {
        if (EXIT_PASS!=(status=CheckTestCase(config->testCases.initCases, 
                                             SERVER_INIT)))
        {
            printf("Basic test group id %d for Server Initialization is "
                   "Not Found. Test aborted\n", SERVER_INIT);
            goto end;
        }
        else
        {
            printf("Server testing started\n");
            if(EXIT_PASS!=(status=Server_Init_Test(config)))
            {
               printf("Server TCP/IP connection Failed. Please refer logs.\n");
               goto end;
            }
            printf("Server testing ended\n");
        }
    }
    if(config!=NULL)
        free(config);
    LOG_PRINT("OpenSSL Testharness End");

end:
    exit(status);
}

int main(int argc, char* argv[])
{
    int status = EXIT_PASS;
    switch(argc)
    {
    case 2: if (strcmp(argv[1],"client")==0 || strcmp(argv[1],"server")==0)
            {
               if (EXIT_PASS!=(status=startTest(DEFAULT_TEST_CASE_CONF_FILE, 
                                                argv[1])))
               {
                   break;
               }    
            }
            else
            {
               status = EXIT_FAIL;
               displayUsageHelp();
               break;
            }

     case 4: if ((strcmp(argv[1],"-f")==0) 
              && (strcmp(argv[2],"client")==0 || strcmp(argv[2],"server")==0))
             {
                 if (!access(argv[3], F_OK))
                 {
                    if (!access(argv[3], R_OK))
                    {
                       if (EXIT_PASS!=(status=startTest(argv[3], argv[2])))
                       {
                           status = EXIT_FAIL;
                           break;
                       }
                    }
                    else
                    {
                       printf("File %s does not have read permission. Please "
                              "check.\n",argv[3]);
                       status = EXIT_FAIL;
                       break;
                    }
                 }
                 else
                 {
                    printf("The File %s is not Found. Please check.\n",argv[3]);
                    status = EXIT_FAIL;
                    break;
                 }
              }
              else
              {
                 displayUsageHelp();
                 break;
              }

      default: displayUsageHelp();
               break;
     }

     exit(status);
}
