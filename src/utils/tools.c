#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "../main.h"

extern void info(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt, ...);

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
    /*
     * return the random number between [1, 254]
     */

    srand((int)time(0) + seed);
    return (1 + (int)(rand() % 254));
}

char *randip(char **buff)
{
    /*
     * return the random ip address
     */

    char *random_ip = (*buff);
    if (!random_ip)
        error(strerror(errno));

    memset(random_ip, 0, MAX_IP_LENGTH);

    int a, b, c, d;
    a = _randnumber(1);
    b = _randnumber(2);
    c = _randnumber(3);
    d = _randnumber(4);
    sprintf(random_ip, "%d.%d.%d.%d", a, b, c, d);
    return random_ip;
}

unsigned short checksum(unsigned short *ptr, int hlen)
{
    /*
     * hlen is the header you want to checksum's length
     * n means how many 16 bit there is
     */
    // 32 bits
    long sum = 0;
    /*
     * IP header 20 Bytes
     * 20 Bytes = 160 Bit = 10 * 16 Bit
     */
    int n = (hlen >> 1);
    for (int i = 0; i < n; i++)
    {
        sum += *ptr++;
    }

    if ((sum >> 16) != 0)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return (unsigned short)~sum;
}