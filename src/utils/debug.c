#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "../main.h"

extern size_t ShowMessage(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern size_t InfoMessage(const char *fmt, ...);
extern size_t DebugMessage(const char *fmt, ...);
extern size_t ErrorMessage(const char *fmt, ...);

size_t ShowMessage(const int message_debug_level, const int user_debug_level, const char *fmt, ...)
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
        return (size_t)0;
    }

    int buff_size = 0;
    char *buff = NULL;
    va_list arg;

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    va_end(arg);

    if (buff_size < 0)
    {
        ErrorMessage("get buff_size failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    // for '\0'
    ++buff_size;
    buff = (char *)malloc(buff_size);
    if (!buff)
    {
        ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    if (buff_size < 0)
    {
        ErrorMessage("get buff_size failed: %s(%d)", strerror(errno), errno);
        if (buff)
        {
            free(buff);
        }
        return (size_t)-1;
    }

    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    printf("\033[0;34m%d-%d-%d %d:%d:%d DEBUG [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buff);
    va_end(arg);
    if (buff)
    {
        free(buff);
    }
    return (size_t)0;
}

size_t InfoMessage(const char *fmt, ...)
{
    /*
     * show the info message
     */

    int buff_size = 0;
    char *buff = NULL;
    va_list arg;

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    va_end(arg);

    if (buff_size < 0)
    {
        ErrorMessage("get buff_size failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    // for '\0'
    ++buff_size;
    buff = (char *)malloc(buff_size);
    if (!buff)
    {
        ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    if (buff_size < 0)
    {
        ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
        if (buff)
        {
            free(buff);
        }
        return (size_t)-1;
    }

    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    // highlight and green
    printf("\033[0;32m%d-%d-%d %d:%d:%d INFO [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buff);
    //printf("\033[0;32m INFO [%s]\033[0m\n", buff);

    va_end(arg);
    if (buff)
    {
        free(buff);
    }
    return (size_t)0;
}

size_t DebugMessage(const char *fmt, ...)
{
    /*
     * show the warning message
     */

    int buff_size = 0;
    char *buff = NULL;
    va_list arg;

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    va_end(arg);

    if (buff_size < 0)
    {
        ErrorMessage("get buff_size failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    // for '\0'
    ++buff_size;
    buff = (char *)malloc(buff_size);
    if (!buff)
    {
        ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    if (buff_size < 0)
    {
        ErrorMessage("get buff_size failed: %s(%d)", strerror(errno), errno);
        if (buff)
        {
            free(buff);
        }
        return (size_t)-1;
    }

    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    // highlight and yellow
    printf("\033[0;35m%d-%d-%d %d:%d:%d WARNING [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buff);

    va_end(arg);
    free(buff);
    return (size_t)0;
}

size_t ErrorMessage(const char *fmt, ...)
{
    // show the error message

    int buff_size = 0;
    char *buff = NULL;
    va_list arg;

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    va_end(arg);

    if (buff_size < 0)
    {
        ErrorMessage("get buff_size failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    // for '\0'
    ++buff_size;
    buff = (char *)malloc(buff_size);
    if (!buff)
    {
        ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    if (buff_size < 0)
    {
        ErrorMessage("get buff_size failed: %s(%d)", strerror(errno), errno);
        if (buff)
        {
            free(buff);
        }
        return (size_t)-1;
    }

    time_t t;
    struct tm *time_struct;
    time(&t);
    time_struct = localtime(&t);
    // highlight and red
    printf("\033[0;31m%d-%d-%d %d:%d:%d ERROR [%s]\033[0m\n", time_struct->tm_year + 1900, time_struct->tm_mon, time_struct->tm_mday, time_struct->tm_hour, time_struct->tm_min, time_struct->tm_sec, buff);
    va_end(arg);
    if (buff)
    {
        free(buff);
    }
    return (size_t)0;
}

void SignalExit(int signo)
{
    // for show message
    DebugMessage("quit the program now");
    exit(0);
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