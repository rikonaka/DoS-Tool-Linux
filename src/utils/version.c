#include <stdio.h>

extern int info(const char *fmt, ...);

// char *version = "v0.1.0";
// static char *version = "0.2.0";
// 2019-03-25
// static char *version = "0.3.0";
// 2020-03-23, new arch now
// static char *version = "1.0.0";
// 2021-01-01, continue work
// static char *version = "1.0.1";
// 2021-01-18
static char *version = "1.0.2";

char *return_version(void)
{
    return version;
}

void version_show(void)
{
    info("dos-tool-linux v%s", version);
}