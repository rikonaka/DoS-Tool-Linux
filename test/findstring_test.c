#include <stdio.h>
#include <string.h>

int FindString(char *source, char *target)
{
    /*
     * return
     * 0 find source include target
     * 1 not include
     */

    char *pt = target;
    char *ps;
    ps = strchr(source, *pt);
    while (*pt)
    {
        if (*pt != *ps)
        {
            return -1;
        }
        ++pt;
        ++ps;
    }

    return 0;
}

int main(void)
{
    char *s = "12345";
    char *t = "23";
    printf("%d\n", FindString(s, t));
    return 0;
}