#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *p1 = "abcdedf";
    printf("%d\n", strlen(p1));

    char *p2 = (char *)malloc(1024 * sizeof(char));
    memset(p2, 0 , 1024);
    printf("%d\n", strlen(p2));

    strcpy(p2, p1);
    printf("%d\n", strlen(p2));
}