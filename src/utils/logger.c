#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>

void info(const char *fmt, ...)
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

    #ifdef DEBUG
    if (buff_size < 0)
    {
        error("get buff_size failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif

    // for '\0'
    ++buff_size;
    buff = (char *)malloc(buff_size);

    #ifdef DEBUG
    if (!buff)
    {
        error("malloc failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);

    #ifdef DEBUG
    if (buff_size < 0)
    {
        error("malloc failed: %s(%d)", strerror(errno), errno);
        if (buff)
        {
            free(buff);
        }
        return -1;
    }
    #endif

    time_t t;
    struct tm *time_st;
    time(&t);
    time_st = localtime(&t);
    // highlight and green
    #if _WIN32
        printf("this code is not tested in windwos\n");
        printf("%d-%d-%d %d:%d:%d INFO [%s]\n", time_st->tm_year + 1900, time_st->tm_mon, time_st->tm_mday, time_st->tm_hour, time_st->tm_min, time_st->tm_sec, buff);
    #elif __linux__
        printf("\033[0;32m%d-%d-%d %d:%d:%d INFO [%s]\033[0m\n", time_st->tm_year + 1900, time_st->tm_mon, time_st->tm_mday, time_st->tm_hour, time_st->tm_min, time_st->tm_sec, buff);
    #endif
    //printf("\033[0;32m DEBUG [%s]\033[0m\n", buff);

    va_end(arg);
    if (buff)
    {
        free(buff);
    }
}

void warning(const char *fmt, ...)
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

    #ifdef DEBUG
    if (buff_size < 0)
    {
        error("get buff_size failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif

    // for '\0'
    ++buff_size;
    buff = (char *)malloc(buff_size);

    #ifdef DEBUG
    if (!buff)
    {
        error("malloc failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);

    #ifdef DEBUG
    if (buff_size < 0)
    {
        error("get buff_size failed: %s(%d)", strerror(errno), errno);
        if (buff)
        {
            free(buff);
        }
        return -1;
    }
    #endif

    time_t t;
    struct tm *time_st;
    time(&t);
    time_st = localtime(&t);
    // highlight and yellow
    #if _WIN32
        printf("this code is not tested in windwos\n");
        printf("%d-%d-%d %d:%d:%d WARNING [%s]\n", time_st->tm_year + 1900, time_st->tm_mon, time_st->tm_mday, time_st->tm_hour, time_st->tm_min, time_st->tm_sec, buff);
    #elif __linux__
        printf("\033[0;33m%d-%d-%d %d:%d:%d WARNING [%s]\033[0m\n", time_st->tm_year + 1900, time_st->tm_mon, time_st->tm_mday, time_st->tm_hour, time_st->tm_min, time_st->tm_sec, buff);
    #endif

    va_end(arg);
    free(buff);
}

void error(const char *fmt, ...)
{
    // show the error message

    int buff_size = 0;
    char *buff = NULL;
    va_list arg;

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);
    va_end(arg);

    #ifdef DEBUG
    if (buff_size < 0)
    {
        error("get buff_size failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif

    // for '\0'
    ++buff_size;
    buff = (char *)malloc(buff_size);

    #ifdef DEBUG
    if (!buff)
    {
        error("malloc failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif

    va_start(arg, fmt);
    buff_size = vsnprintf(buff, buff_size, fmt, arg);

    #ifdef DEBUG
    if (buff_size < 0)
    {
        error("get buff_size failed: %s(%d)", strerror(errno), errno);
        if (buff)
        {
            free(buff);
        }
        return -1;
    }
    #endif

    time_t t;
    struct tm *time_st;
    time(&t);
    time_st = localtime(&t);
    // highlight and red
    #if _WIN32
        printf("this code is not tested in windwos\n");
        printf("%d-%d-%d %d:%d:%d ERROR [%s]\n", time_st->tm_year + 1900, time_st->tm_mon, time_st->tm_mday, time_st->tm_hour, time_st->tm_min, time_st->tm_sec, buff);
    #elif __linux__
        printf("\033[0;31m%d-%d-%d %d:%d:%d ERROR [%s]\033[0m\n", time_st->tm_year + 1900, time_st->tm_mon, time_st->tm_mday, time_st->tm_hour, time_st->tm_min, time_st->tm_sec, buff);
    #endif

    va_end(arg);
    if (buff)
    {
        free(buff);
    }

    exit(-1);
}

void wronginput(const char *input_parameter)
{
    error("please check your %s option", input_parameter);
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