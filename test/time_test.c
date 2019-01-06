#include <time.h>
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
    time_t t;
    //struct tm *p;
    time(&t);
    printf("%ld\n", t);
    printf("%d\n", (int)(t));
}