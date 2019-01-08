#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include "../main.h"
#include "debug.h"

int SplitURL(const char *url, char **host, char **suffix, int *port)
{
    /*
     * This function will split the url
     * Example with url = 'http://192.168.20.1:8080/index.html'
     * After parse:
     *    host = "192.168.20.1"
     *    suffix = "index.html"
     *    port = 8080
     * 
     * input:
     *     url
     * output:
     *     host
     *     suffix
     *     port
     */

    char tr1[MAX_URL_LENGTH];
    strncpy(tr1, url, MAX_URL_LENGTH);
    char *ptr1 = tr1;
    char *ptr2;
    char *ptr3;

    ptr1 = strchr(ptr1, '/');
    if (!ptr1 || *(++ptr1) != '/')
    {
        DisplayError("Please check your URL address");
        return -1;
    }
    /* cut the 'http:\\' */
    *ptr1 = '\0';
    ++ptr1;

    ptr2 = strchr(ptr1, '/');

    if (!ptr2)
    {
        DisplayError("Please check your URL address");
        return -1;
    }
    else
    {
        // Execute here mean program found the '/'
        // Now ptr1 and ptr2 status is here:
        //      ptr1              ptr2
        //       |                 |
        // http://192.168.20.1:8080/index.html
        // len is same as the strlen("192.168.20.1")
        *ptr2 = '\0';

        // Only copy the IP(192.168.20.1:8080) address to host
        // There sentence is judge the (index.html) is existed or not
        if (*(++ptr2))
        {
            // Copy the 'index.html' to file except the frist character '\'
            // Fill in the last blank with '\0'
            *suffix = ptr2;
        }
    }

    // Now split host and ip
    ptr3 = strchr(ptr1, ':');
    if (!ptr3)
    {
        DisplayWarning("No port found, use default value <%d> now", PORT_DEFAULT);
        *port = PORT_DEFAULT;
    }
    else
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
        *ptr3 = '\0';
        ++ptr3;
        // Make the port point to (int)8080
        *port = atoi(ptr3);
    }
    *host = ptr1;
    return 0;
}

int GetRandomPassword(char *rebuf, const pInput process_result)
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

/*
int main(void)
{
    char *input = "http://192.168.1.1:80/index.html";
    char *output;
    char *host;
    char *suffix;
    int port;

    SplitURL(input, &host, &suffix, &port);
    printf("host: %s, suffix: %s, port: %d\n", host, suffix, port);
    return 0;
}
*/