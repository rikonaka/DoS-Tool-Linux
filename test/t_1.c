#include <stdio.h>

extern int test(void);
#define global 1

int main(void)
{
    printf("%d", global);
    test();
    return 0;

}