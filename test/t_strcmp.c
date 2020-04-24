#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *Strip(char *dst, const char *src)
{
    /* delete the space which in the start of string and end of string*/
    int i = 0;
    int j = 0;

    while ((src[i] == ' ') && (src[i] != '\0'))
    {
        ++i;
    }

    while (src[i] != '\0')
    {
        dst[j] = src[i];
        ++j;
        ++i;
    }

    --j;
    while ((dst[j] == ' ') && (dst[j] != '\0'))
    {
        dst[j] = '\0';
        --j;
    }

    return dst;
}

int main(int argc, char *argv[])
{
    char *src = "      1 2 3 4    5 7      ";
    char *dst = (char *)malloc(strlen(src) * sizeof(char));

    dst = Strip(dst, src);
    printf("[%s]\n", dst);

    return 0;
}