/* File: debug.c 
 * Auth: isinstance
 * Date: 20171102
 * Mail: no
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1024
#endif

void debug(const int debugflag, const int debuglevel, const char *fmt, ...)
{
    /*
     * debug(1, 2, "string");
     * debug mode use
     * 'debugflag' is user set to show or not show some nonsense message
     * 'debuglevel' is the level you want to see
     */

    va_list arg;
    char *buf = (char *)malloc(BUFFER_SIZE);
    //int done;

    va_start(arg, fmt);
    // Magic here
    if (vsprintf(buf, fmt, arg) > 0)
    {
        if (debugflag != 0)
        {
            if (debugflag >= debuglevel)
            {
                printf("DEBUG-%d[%d]: [%s]\n", debugflag, debuglevel, buf);
            }
        }
    }
    // Original _printf code
    //done = vfprintf(buf, fmt, arg);
    //done = vfprintf(stdout, fmt, arg);
    va_end(arg);

    // Original _printf code
    //return done;
    free(buf);
}

/*
int main(void)
{
    int flag = 2;
    int level = 2;

    char *str1 = "ya";
    char *str2 = "ho";
    char *str3 = "yo";

    debug(flag, level, "Show me some magic here %s %s %s", str1, str2, str3);
    return 0;
}
*/