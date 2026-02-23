/* ------------------------------------------------------------ *
 * file:        logger.c                                	*
 * purpose:     This file is responsible to write the log file  *
 * author:      05/02/2017 rdwivedi                             *
 * ------------------------------------------------------------ */

#include "logger.h"

FILE *fp ;
char *buf, *ret;

void check_ssl_api_error(char *functionName)
{
    char *error = NULL;
    error = ossl_err_as_string();
    if (error!=NULL)
         LOG_PRINT("%s::FAILED, error:: %s", functionName, error);
    else
         LOG_PRINT("%s::FAILED", functionName);
}

char* ossl_err_as_string()
{ 
    BIO 	*bio = NULL;
    char	*buf = NULL;
    size_t 	 len;
    const char *SSL_Error_Tags[] ={"pid", "error", "error code", "library name",
                                   "function name", "reason string", "file name",
                                   "line", "optional text message"};
    char *key, *strError=NULL;
    char value[1024];
    int count=0;  
    size_t needed;  
    bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    len = BIO_get_mem_data (bio, &buf);
    ret = (char*)calloc(1, 1+len);
    if (ret)
    {
        memcpy (ret, buf, len);
    }
    key = strtok(ret,":");
    if(key!=NULL)
    {
    	   memset(value,'\0',1024);    
    	   snprintf(value, 1024, "[%s:%s]", SSL_Error_Tags[count], key);
    	   while(count<8)
    	   {
		          key = strtok(NULL,":");
		          snprintf(value, 1024, "%s  [%s:%s]", value, SSL_Error_Tags[count+1], key);
		          count++;
    	   }
    	   BIO_free (bio);
    	   needed=strlen(value);
    	   strError=(char*)malloc(needed+1);
    	   memset(strError, '\0', needed+1);
    	   strncpy(strError, value, needed+1);
    	   return strError;
    }
    return NULL;
}

char* print_time()
{
    buf = (char*)malloc(20);
    time_t now = time(NULL);
    strftime(buf, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
    return buf;
}

void log_print(char* filename, int line, const char* functionName, char *fmt,...)
{
    va_list  list;
    char    *p, *r;
    int      e;
 
    fp = fopen (LOGGER_FILE_NAME,"a+");
    fprintf(fp,"[%s] ", print_time()); 
    fprintf(fp,"[%s:%d][%s()] ", filename, line, functionName);
    va_start( list, fmt );
 
    for ( p = fmt ; *p ; ++p )
    {
        if ( *p != '%' )
        {
            fputc( *p,fp );
        }
        else
        {
            switch ( *++p )
            {
                /* string */
            case 's':
            {
                r = va_arg( list, char * );
                fprintf(fp,"%s", r);
                continue;
            }
 
            /* integer */
            case 'd':
            {
                e = va_arg( list, int );
                fprintf(fp,"%d", e);
                continue;
            }
 
            default:
                fputc( *p, fp );
            }
        }
    }
    va_end( list );
    fputc( '\n', fp );
    fclose(fp);
    free(buf);
}
