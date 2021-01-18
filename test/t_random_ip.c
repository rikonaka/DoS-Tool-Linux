#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

static int _randnumber(int seed)
{
    /*
     * return the random number between [1, 254]
     */

    srand((int)time(0) + seed);
    return (1 + (int)(rand() % 254));
}

char *randip(char **buff)
{
    // return the random ip address

    char *random_ip = (*buff);
    // 012345678901234
    // 255.255.255.255
    
    memset(random_ip, 0, 32);
    /*
     * 1   2   3 4
     * 192.168.1.1
     */
    int a, b, c, d;
    a = _randnumber(1);
    b = _randnumber(2);
    c = _randnumber(3);
    d = _randnumber(4);
    sprintf(random_ip, "%d.%d.%d.%d", a, b, c, d);

    return random_ip;
}

int main(void)
{
    char *random_source_ip = (char *)malloc(sizeof(char) * 32);
    random_source_ip = randip(&random_source_ip);

    return 0;
}