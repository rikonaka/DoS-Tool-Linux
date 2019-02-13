#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmt, ...);
extern int DisplayError(const char *fmt, ...);

// char *version = "v0.10";
char *version = "v0.20";

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
        DisplayError("GetCurrentVersion strncpy failed");
        return NULL;
    }
    return (*output);
}