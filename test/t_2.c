#include <stdio.h>

int test(void)
{
    int i = 10;
    printf("%d", i);
    #ifdef global
    printf("%d", global);
    #endif

    return 0;
}