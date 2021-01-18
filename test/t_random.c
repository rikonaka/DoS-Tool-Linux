#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

int randport(void)
{
    /*
     * return randome port from [1, 65535]
     */

    srand((int)time(0));
    return (1 + (int)(rand() % 65535));
}

static int _randnumber(int seed)
{
    srand((int)time(0) + seed);
    return (1 + (int)(rand() % 10));
}

int main(void)
{
    int padding_size;
    for (int i = 0; i < 10; i++)
    {
        padding_size = (1 + randport() % 8);
        printf("%d\n", padding_size);
        sleep(1);
    }
    return 0;
}

