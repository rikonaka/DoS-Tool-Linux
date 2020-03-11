#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../main.h"

extern int ShowMessage(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int InfoMessage(const char *fmt, ...);
extern int DebugMessage(const char *fmt, ...);
extern int ErrorMessage(const char *fmt, ...);

// char *version = "v0.10";
// const char *version = "0.20";
const char *version = "0.30"; // 2019-3-25

void FreeGetCurrentVersionBuff(char *p)
{
    if (p)
    {
        free(p);
    }
}

char *GetCurrentVersion(char **output)
{
    // return the current version of this code
    *output = (char *)malloc(sizeof(char));
    if (!strncpy((*output), version, strlen(version)))
    {
        ErrorMessage("GetCurrentVersion strncpy failed");
        return (char *)NULL;
    }
    return (*output);
}