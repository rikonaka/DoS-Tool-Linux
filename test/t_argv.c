#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    for (int i = 0; i < argc; i++)
    {
        printf("argv: %s\n", argv[i]);
    }
    char *test = (char *)malloc(10);
    memset(test, 0, 10);

    return 0;
}