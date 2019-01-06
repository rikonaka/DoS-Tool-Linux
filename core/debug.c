#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include "debug.h"

int Log(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...)
{
    /*
     * Log(1, 2, "string");
     * 'user_debug_level' is the level you want to see
     * 'message_debug_level' is used to identified the message log level
     */

    va_list arg;
    char *buf = (char *)malloc(MAX_LOG_BUF_SIZE);
    time_t t;
    struct tm *timeinfo;
    time(&t);
    timeinfo = localtime(&t);
    //int done;
    if (!buf)
    {
        fprintf(stderr, "Log-Error: %s\n", strerror(errno));
        return 1;
    }

    va_start(arg, fmtstring);
    // Magic here
    if (vsprintf(buf, fmtstring, arg) > 0)
    {
        if (message_debug_level != 0)
        {
            if (message_debug_level >= user_debug_level)
            {
                printf("%s: [%s]\n", asctime(timeinfo), buf);
            }
        }
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

int ShowUsage()
{
    /*
        show the useage info
     */
    char *usage = "\nUsage:   dostool\n"
                  "Example: ./dostool -a 1\n"
                  "         ./dostool -a 0\n"
                  "         ./dostool -a 0 -u admin\n"
                  "         ./dostool -a 0 -U \"/home/test/username.txt\"\n\n"
                  "         -a   Attack mode\n"
                  "         -d   Debug mode\n"
                  "         -D   Show more debug mode\n"
                  "         -u   Use user-provided username (must use with -a 0)\n"
                  "         -U   Use user-provided username file (must use with -a 0)\n"
                  "         -p   Use user-provided password (must use with -a 0)\n"
                  "         -P   Use user-provided password file (must use with -a 0)\n";

    printf("%s", usage);
    return 0;
}