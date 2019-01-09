#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#include "../main.h"
#include "debug.h"

int SplitURL(const char *url, char **host, char **suffix, int *port)
{
    /* rewrite it */
    int i;
    /*      12           3 */
    /* http://192.168.1.1/index.html */
    char *first_slash_position = strchr(url, '/');
    char *second_slash_position = strchr((first_slash_position + 1), '/');
    char *third_slash_position = strchr((second_slash_position + 1), '/');
    /* if url like http://192.168.1.1:8080/index.html */
    char *colon_position = strchr((second_slash_position + 1), ':');
    char *ptmp;

    char *host_buff = (char *)malloc(sizeof(char));
    char *suffix_buff = (char *)malloc(sizeof(char));
    char *port_buff = (char *)malloc(sizeof(char));
    memset(host_buff, '\0', sizeof(host_buff));
    memset(suffix_buff, '\0', sizeof(suffix_buff));
    memset(port_buff, '\0', sizeof(suffix_buff));

    /* copy the host to host_buff */
    ptmp = (second_slash_position + 1);
    i = 0;
    while (ptmp != colon_position && ptmp != third_slash_position)
    {
        host_buff[i] = *ptmp;
        ++i;
        ++ptmp;
    }
    host_buff[i] = '\0';

    /* copy the port if existed */
    if (colon_position)
    {
        ptmp = (colon_position + 1);
        i = 0;
        while (ptmp != third_slash_position)
        {
            port_buff[i] = *ptmp;
            ++i;
            ++ptmp;
        }
    }
    else
    {
        /* if can not found the : use the default value */
        sprintf(port_buff, "%d", PORT_DEFAULT);
    }
    /* copy the suffix to suffix_buff */
    ptmp = (third_slash_position + 1);
    i = 0;
    while (*ptmp)
    {
        suffix_buff[i] = *ptmp;
        ++i;
        ++ptmp;
    }
    suffix_buff[i] = '\0';

    *host = host_buff;
    *suffix = suffix_buff;
    *port = atoi(port_buff);

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
    //char *input = "http://192.168.1.1:80/index.html";
    char *input = "http://192.168.1.1/index.html";
    char *output;
    char *host;
    char *suffix;
    int port;

    SplitURL(input, &host, &suffix, &port);
    printf("host: %s, suffix: %s, port: %d\n", host, suffix, port);
    return 0;
}
*/