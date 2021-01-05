#include <stdio.h>

// char *version = "v0.10";
// static char *version = "0.20";
// 2019-03-25
// static char *version = "0.30";
// 2020-03-23, new arch now
// static char *version = "1.00";
// 2021-01-01, continue work
static char *version = "1.01";

char *ReturnVersion(void)
{
    return version;
}

void VersionShow(void)
{
    printf("dos-tool-linux v%s\n", version);
}