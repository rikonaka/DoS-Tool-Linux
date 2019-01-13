#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "../main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);
extern int DisplayInfo(const char *fmtstring, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmtstring, ...);

int FreeSplitURLBuff(pSplitURLOutput p)
{
    free(p->host);
    free(p->suffix);
    free(p);
    return 0;
}

int SplitURL(pSplitURLOutput *output, const char *url)
{
    // rewrite this function at 2019-1-10
    int i;
    (*output) = (pSplitURLOutput)malloc(sizeof(SplitURLOutput));
    //      12           3
    // http://192.168.1.1/index.html
    char *first_slash_position = strchr(url, '/');
    char *second_slash_position = strchr((first_slash_position + 1), '/');
    char *third_slash_position = strchr((second_slash_position + 1), '/');
    /* if url like http://192.168.1.1:8080/index.html */
    char *colon_position = strchr((second_slash_position + 1), ':');
    char *ptmp;

    char *host_buff = (char *)malloc(sizeof(char));
    char *suffix_buff = (char *)malloc(sizeof(char));
    char *port_buff = (char *)malloc(sizeof(char));
    memset(host_buff, 0,sizeof(char));
    memset(suffix_buff, 0, sizeof(char));
    memset(port_buff, 0, sizeof(char));

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
        port_buff[i] = '\0';
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

    (*output)->host = host_buff;
    (*output)->suffix = suffix_buff;
    (*output)->port = atoi(port_buff);

    free(port_buff);
    return 0;
}

int FreeRandomPasswordBuff(char *password)
{
    free(password);
    return 0;
}

int GetRandomPassword(char **rebuf, unsigned int seed, const int length)
{
    /*
     * generate the random password and return
     */

    char *r_password = (char *)malloc(MAX_PASSWORD_LENGTH);
    memset(r_password, 0, MAX_PASSWORD_LENGTH);
    int r_num;
    int i;

    if (seed > 1024)
    {
        seed = 0;
    }
    // srand is here
    srand((int)time(0) + seed);

    for (i = 0; i < length; i++)
    {
        // [a, b] random interger
        // [33, 126] except space[32]
        // 92 = 126 - 33 - 1
        r_num = 33 + (int)(rand() % 92);
        if (isprint(r_num))
        {
            sprintf(r_password, "%s%c", r_password, r_num);
        }
    }
    *rebuf = r_password;
    return 0;
}

/*
static int TestStringList(const pStringHeader output)
{
    pStringNode p = output->next;
    DisplayInfo("Linked list length: %d", output->length);
    while (p)
    {
        DisplayInfo("%s", p->username);
        p = p->next;
    }
}
*/

int FreeProcessFileBuff(pStringHeader p)
{
    pStringNode n = p->next;
    pStringNode n_next = n->next;
    while (n_next)
    {
        //DisplayInfo("Free <%s> space now", n->username);
        free(n);
        --(p->length);
        n = n_next;
        n_next = n_next->next;
    }

    if (p->length != 1)
    {
        DisplayWarning("Free the space error");
    }

    free(n);
    free(p);
    return 0;
}

int ProcessFile(char *path, pStringHeader *output, int flag)
{
    // use the structure store the username list
    // flag == 0 -> username list
    // flag == 1 -> password list
    size_t LENGTH;
    if (flag)
    {
        LENGTH = MAX_PASSWORD_LENGTH;
    }
    else
    {
        LENGTH = MAX_USERNAME_LENGTH;
    }

    (*output) = (pStringHeader)malloc(sizeof(StringHeader));
    pStringNode u_list;
    (*output)->length = 0;
    (*output)->next = NULL;
    char space[LENGTH];
    char ch;
    size_t u_length = 0;

    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        DisplayError("Error: Can not open the username file");
        return -1;
    }
    while (!feof(fp))
    {
        // if stack error, change here
        memset(space, 0, LENGTH);
        ch = fgetc(fp);
        while (ch != '\n' && ch != '\r' && !feof(fp))
        {
            sprintf(space, "%s%c", space, ch);
            //DisplayInfo("%c", ch);
            ch = fgetc(fp);
        }

        u_length = strlen(space);
        if (u_length > 0)
        {
            u_list = (pStringNode)malloc(sizeof(StringNode));
            u_list->next = (*output)->next;
            (*output)->next = u_list;
            //DisplayInfo("%ld", u_length);
            // make a space for /0
            u_list->username = (char *)malloc(u_length + 1);
            memset(u_list->username, 0, u_length + 1);
            strncpy(u_list->username, space, u_length);
            ++((*output)->length);
            //DisplayInfo("%s", u_list->username);
            //DisplayInfo("%d", (*output)->length);
        }
    }
    fclose(fp);
    return 0;
}

/*
int main(void)
{
    //char *input = "http://192.168.1.1:80/index.html";
    char *input = "http://192.168.1.1/index.html";
    pSplitURLOutput s;

    SplitURL(&s, input);
    printf("host: %s, suffix: %s, port: %d\n", s->host, s->suffix, s->port);
    FreeSplitURL(s);

    char *random;
    GetRandomPassword(&random, 10, 8);
    DisplayInfo("%s", random);
    FreeRandomPasswordBuff(random);

    char *path = "/home/hero/Documents/Code/DoS-Tool/wordlists/others/best1050.txt";
    pStringHeader p;
    ProcessFile(path, &p, 0);
    //TestCharList(p);
    FreeProcessFileBuff(p);

    return 0;
}
*/