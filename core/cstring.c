#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../main.h"

int ProcessURL(const char *url, char *host, char *file, int *port)
{
    /*
     * This function will split the url
     * Example with url = 'http://192.168.20.1:8080/index.html'
     * After parse:
     *    host = "192.168.20.1"
     *    file = "index.html"
     *    port = 8080
     */
    char *ptr1, *ptr2;
    int len = 0;
    if (!url || !host || !file || !port)
    {
        return 1;
    }

    ptr1 = (char *)url;

    /* not support https now */
    if (strncmp(ptr1, "http://", strlen("http://")) == 0)
    {
        // jump offset
        ptr1 += strlen("http://");
    }
    else
    {
        return 1;
    }

    // search the characters '/'
    ptr2 = strchr(ptr1, '/');

    // if not found '/'
    // strchr return null
    // else return pointer
    if (ptr2)
    {
        // Execute here mean program found the '/'
        // Now ptr1 and ptr2 status is here:
        //       ptr1             ptr2
        //        |                |
        // http://192.168.20.1:8080/index.html
        // len is same as the strlen("192.168.20.1")
        len = strlen(ptr1) - strlen(ptr2);

        // Only copy the IP(192.168.20.1:8080) address to host
        memcpy(host, ptr1, len);

        // Make the position backward the '192.168.20.1:8080' become '\0'
        host[len] = '\0';

        // There sentence is judge the (index.html) is existed or not
        if (*(ptr2 + 1))
        {
            // Copy the 'index.html' to file except the frist character '\'
            memcpy(file, ptr2 + 1, strlen(ptr2) - 1);
            // Fill in the last blank with '\0'
            file[strlen(ptr2) - 1] = '\0';
        }
    }
    else
    {
        // If not existed the '/index.html' string
        // Just copy the ptr1 to host
        memcpy(host, ptr1, strlen(ptr1));
        // Also fill in the last character with '\0'
        host[strlen(ptr1)] = '\0';
    }

    // Now split host and ip
    ptr1 = strchr(host, ':');
    if (ptr1)
    {
        /* Now ptr1 status:
         *            ptr1
         *             |
         * 192.168.20.1:8080
         * -----------------
         * Some important C skill:
         * 'pstr++' is not same as '++ptr1'
         * '*ptr1++ = '\0' excute step:
         * 1. ptr1 = '\0';
         * 2. ptr1 += 1;
         */
        *ptr1++ = '\0';
        // Make the port point to (int)8080
        *port = atoi(ptr1);
    }
    else
    {
        *port = PORT_DEFAULT;
    }
    return 0;
}

int IncludeString(char *source, char *target)
{
    /*
     * return
     * 0 source include target
     * 1 not include
     */

    char *pt = target;
    char *ps;
    ps = strchr(source, *pt);
    while (*pt)
    {
        if (*pt != *ps)
        {
            return 1;
        }
        ++pt;
        ++ps;
    }

    return 0;
}

static int GetRandomPassword(char *rebuf, const pInput process_result)
{
    /*
     * generate the random password and return
     */

    char str[MAX_PASSWORD_LENGTH] = {'\0'};
    int random_number_1;
    int seed = process_result->seed;
    int i;

    if (seed > 1024)
    {
        seed = 0;
    }
    // srand is here
    srand((int)time(0) + seed);

    for (i = 0; i < process_result->random_password_length; i++)
    {
        // [a, b] random interger
        // [33, 126] except space[32]
        // 92 = 126 - 33 - 1
        random_number_1 = 33 + (int)(rand() % 92);
        if (isprint(random_number_1))
        {
            sprintf(str, "%s%c", str, random_number_1);
        }
    }
    strncpy(rebuf, str, MAX_PASSWORD_LENGTH);
    return 0;
}