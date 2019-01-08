#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "debug.h"

int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...)
{
    /*
     * DisplayDebug(1, 2, "string");
     * 'user_debug_level' is the level you want to see
     * 'message_debug_level' is used to identified the message log level
     */

    /* DEBUG_OFF */
    if (!user_debug_level || user_debug_level < message_debug_level)
    {
        /* return in here, less code run */
        return 0;
    }

    va_list arg;
    char *buf = (char *)malloc(MAX_LOG_BUF_SIZE);
    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    //int done;
    if (!buf)
    {
        return -1;
    }

    va_start(arg, fmtstring);
    // Magic here
    if (vsprintf(buf, fmtstring, arg) > 0)
    {
        printf("\033[0;32m%d-%d-%d %d:%d:%d INFO [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buf);
    }
    // Original _printf code
    //done = vfprintf(buf, fmtstring, arg);
    //done = vfprintf(stdout, fmtstring, arg);
    va_end(arg);

    // Original _printf code
    //return done;
    free(buf);
    return 0;
}

int DisplayInfo(const char *fmtstring, ...)
{
    /*
     * show the info message
     */

    va_list arg;
    char *buf = (char *)malloc(MAX_LOG_BUF_SIZE);
    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    if (!buf)
    {
        return -1;
    }

    va_start(arg, fmtstring);
    if (vsprintf(buf, fmtstring, arg) > 0)
    {
        /* highlight and green */
        printf("\033[0;32m%d-%d-%d %d:%d:%d INFO [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buf);
    }

    va_end(arg);
    free(buf);
    return 0;
}

int DisplayWarning(const char *fmtstring, ...)
{
    /*
     * show the warning message
     */

    va_list arg;
    char *buf = (char *)malloc(MAX_LOG_BUF_SIZE);
    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    if (!buf)
    {
        return -1;
    }

    va_start(arg, fmtstring);
    if (vsprintf(buf, fmtstring, arg) > 0)
    {
        /* highlight and green */
        printf("\033[0;33m%d-%d-%d %d:%d:%d WARNING [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buf);
    }

    va_end(arg);
    free(buf);
    return 0;
}

int DisplayError(const char *fmtstring, ...)
{
    /*
     * show the error message
     */

    va_list arg;
    char *buf = (char *)malloc(MAX_LOG_BUF_SIZE);
    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    if (!buf)
    {
        return -1;
    }

    va_start(arg, fmtstring);
    if (vsprintf(buf, fmtstring, arg) > 0)
    {
        /* highlight and red */
        printf("\033[0;31m%d-%d-%d %d:%d:%d ERROR [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buf);
    }

    va_end(arg);
    free(buf);
    return 0;
}

/*
int main(void)
{
    char *test = "ABCDabcd";
    DisplayDebug(2, 1, test);
    DisplayInfo(test);
    DisplayWarning(test);
    DisplayError(test);

    return 0;
}
*/