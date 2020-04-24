#include <stdio.h>
#include <stdlib.h>

typedef struct test_struct
{
    struct test_struct *next;
    char *str;
    int value;
} *pTest, Test;

void free_test(pTest input)
{
    if (input)
    {
        if (input->next)
        {
            free(input->next);
        }
        if (input->str)
        {
            free(input->str);
        }
        free(input);
    }
}

int main(int argc, char *argv[])
{
    pTest test = (pTest)malloc(sizeof(Test));
    test->value = 10;
    test->str = (char *)malloc(10);
    strcpy(test->str, "abcdefg");

    free_test(test);
    size_t s = sizeof(test);
    
    return 0;
}