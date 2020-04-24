#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct test_struct
{
    char *a;
    char *b;
    char *c;
    int d;
} Test, *pTest;

int main(void)
{
    pTest test = (pTest)malloc(sizeof(Test));
    test->a = (char *)malloc(2);

    memset(test, 0, sizeof(test));

    return 0;
}