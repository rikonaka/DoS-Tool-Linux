#include <stdlib.h>
#include <stdio.h>

typedef struct test_struct
{
    char *a;
    char *b;
    char *c;
    int d;
} Test, *pTest;

int main(int argc, char *argv[])
{
    pTest test = (pTest)malloc(sizeof(Test));

    free(test);
    return 0;
}