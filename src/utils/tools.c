#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "../main.h"

#define GEN_USERNAME 0
#define GEN_PASSWORD 1

// temp use
#define IP_BUFFER_SIZE 1024

char *StripCopy(char *dst, const char *src)
{
    /* delete the space which in the start and end of string*/
    int i = 0;
    int j = 0;

    while ((src[i] == ' ') && (src[i] != '\0'))
    {
        ++i;
    }

    while (src[i] != '\0')
    {
        dst[j] = src[i];
        ++j;
        ++i;
    }

    --j;
    while ((dst[j] == ' ') && (dst[j] != '\0'))
    {
        dst[j] = '\0';
        --j;
    }

    return dst;
}

int AnalysisAddress(const char *addr)
{

    if (strstr(addr, "https"))
    {
        /* https */
        return ADDRESS_TYPE_HTTPS;
    }
    else if (strstr(addr, "http"))
    {
        /* http */
        return ADDRESS_TYPE_HTTP;
    }
    else
    {
        /* ip address */
        return ADDRESS_TYPE_IP;
    }
    
    return -1;
}

static size_t RandomIPNumber(int seed, int *random_num)
{
    // return the random number between 1-255

    // srand is here
    srand((int)time(0) + seed);

    // [a, b] random interger
    // [1, 254] except space[32]
    // 252 = 254 - 1 - 1
    *random_num = 1 + (int)(rand() % 252);
    return (*random_num);
}

size_t FakeAddress(char **output)
{
    // return the random ip address

    int i;
    int random_num = 0;
    // 012345678901234
    // 255.255.255.255
    (*output) = (char *)malloc(MAX_ADDRESS_LENGTH);
    if (!(*output))
    {
        ErrorMessage("GetRandomIP malloc failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }
    if (!memset((*output), 0, strlen(*output)))
    {
        ErrorMessage("GetRandomIP memset failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }
    char *ip = (char *)malloc(MAX_ADDRESS_LENGTH);

    // 1   2   3 4
    // 192.168.1.1
    for (i = 0; i < 4; i++)
    {
        // ip has four num like 192 168 1 1
        RandomIPNumber(i, &random_num);
        sprintf(ip, "%s.%d", ip, random_num);
    }

    // delete the first character '.'
    char *delete = ip + 1;
    strncpy((*output), delete, strlen(delete));
    return sizeof(*output);
}

size_t FakePort(int *output)
{
    // return randome port from 1 to 9999

    int random_number = 0;

    // srand is here
    srand((int)time(0));

    // [a, b] random interger
    // [1, 9999] except space[32]
    // 9997 = 9999 - 1 - 1
    // 65533 = 65536 - 1 - 1
    random_number = 1 + (int)(rand() % 65533);
    *output = random_number;
    return (*output);
}

size_t LocateStrNodeElement(const pStrHeader p, pStrNode *element, const size_t loc)
{
    // locate the str linked list element
    if (loc < 0 || loc > p->length)
    {
        ErrorMessage("loc illegal");
        return (size_t)-1;
    }
    size_t count = 0;
    pStrNode t = p->next;
    while (count != loc)
    {
        t = t->next;
        ++count;
    }

    *element = t;
    return count;
}

void FreeProcessACKIPListBuff(pStrHeader p)
{
    // free it
    pStrNode n = p->next;
    pStrNode n_next = n->next;
    while (n_next)
    {
        //DisplayInfo("Free <%s> space now", n->username);
        if (n)
        {
            free(n);
        }
        --(p->length);
        n = n_next;
        n_next = n_next->next;
    }

    if (p->length != 1)
    {
        WarningMessage("Free the space error");
    }

    if (n)
    {
        free(n);
    }
    if (p)
    {
        free(p);
    }
}

size_t ProcessACKIPListFile(pStrHeader *output)
{

    (*output) = (pStrHeader)malloc(sizeof(StrHeader));
    if (!(*output))
    {
        ErrorMessage("ProcessACKIPListFile malloc failed");
        return (size_t)-1;
    }

    pStrNode str_node;
    (*output)->length = 0;
    (*output)->next = NULL;
    char buff[IP_BUFFER_SIZE] = {'\0'};
    char buff_s[IP_BUFFER_SIZE] = {'\0'};
    char ch;
    size_t str_length = 0;
    size_t count = 0;

    // the file path and file name is default here
    FILE *fp = fopen(ACK_IP_LIST_NAME, "r");
    if (!fp)
    {
        ErrorMessage("can not open the ack ip list file: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    while (!feof(fp))
    {
        // if stack error, change here
        memset(buff, 0, IP_BUFFER_SIZE);

        ch = fgetc(fp);
        while (ch && ch != '\n' && ch != '\r' && !feof(fp))
        {
            sprintf(buff_s, "%s%c", buff, ch);
            strncpy(buff, buff_s, strlen(buff_s));
            //DisplayInfo("%c", ch);
            ch = fgetc(fp);
        }

        str_length = strlen(buff);
        if (str_length > 0 && buff[0] != '#')
        {
            //DisplayInfo("str_length: %d", str_length);
            str_node = (pStrNode)malloc(sizeof(StrNode));
            if (!str_node)
            {
                ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
                return (size_t)-1;
            }
            str_node->next = (*output)->next;
            (*output)->next = str_node;
            // make a space for /0
            str_node->str = (char *)malloc(str_length + 1);
            memset(str_node->str, 0, str_length);
            strncpy(str_node->str, buff, str_length);
            // init the node lock as 0
            ++((*output)->length);
            ++count;
        }
    }
    fclose(fp);
    return sizeof(*output);
}

void FreeProcessDNSIPListBuff(pStrHeader p)
{
    // free it
    pStrNode n = p->next;
    pStrNode n_next = n->next;
    while (n_next)
    {
        //DisplayInfo("Free <%s> space now", n->username);
        if (n)
        {
            free(n);
        }
        --(p->length);
        n = n_next;
        n_next = n_next->next;
    }

    if (p->length != 1)
    {
        WarningMessage("Free the space error");
    }

    if (n)
    {
        free(n);
    }
    if (p)
    {
        free(p);
    }
}

size_t ProcessDNSIPListFile(pStrHeader *output)
{
    // return NULL = failed
    // return something = success

    (*output) = (pStrHeader)malloc(sizeof(StrHeader));
    if (!(*output))
    {
        ErrorMessage("ProcessDNSIPListFile malloc failed");
        return (size_t)-1;
    }

    pStrNode str_node;
    (*output)->length = 0;
    (*output)->next = NULL;
    char buff[IP_BUFFER_SIZE + 1];
    char buff_s[IP_BUFFER_SIZE + 1];
    char ch;
    size_t str_length = 0;
    size_t count = 0;

    // the file path and file name is default here
    FILE *fp = fopen(DNS_IP_LIST_NAME, "r");
    if (!fp)
    {
        ErrorMessage("can not open the ack ip list file: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    while (!feof(fp))
    {
        // if stack error, change here
        memset(buff, 0, IP_BUFFER_SIZE + 1);

        ch = fgetc(fp);
        while (ch && ch != '\n' && ch != '\r' && !feof(fp))
        {
            sprintf(buff_s, "%s%c", buff, ch);
            strncpy(buff, buff_s, strlen(buff_s));
            //DisplayInfo("%c", ch);
            ch = fgetc(fp);
        }

        str_length = strlen(buff);
        if (str_length > 0 && buff[0] != '#')
        {
            //DisplayInfo("str_length: %d", str_length);
            str_node = (pStrNode)malloc(sizeof(StrNode));
            if (!str_node)
            {
                ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
                return (size_t)-1;
            }
            str_node->next = (*output)->next;
            (*output)->next = str_node;
            // make a space for /0
            str_node->str = (char *)malloc(str_length + 1);
            memset(str_node->str, 0, str_length + 1);
            memcpy(str_node->str, buff, str_length + 1);
            // init the node lock as 0
            ++((*output)->length);
            ++count;
        }
    }
    fclose(fp);
    return sizeof(*output);
}

void ProcessACKIPListFileTest(void)
{
    InfoMessage("Enter ProcessACKIPLIstFileTest");
    pStrHeader header;
    ProcessACKIPListFile(&header);
    //DisplayInfo(">>> 2 <<<");
    InfoMessage("Length: %ld", header->length);
    //printf("%ld", header->length);
    pStrNode node = header->next;
    while (node)
    {
        InfoMessage("Value: %s", node->str);
        node = node->next;
    }

    FreeProcessACKIPListBuff(header);
}

size_t SplitIPForThread(pIPList_Thread *output, const pParameter input, const pStrHeader str_header)
{
    // split the whole ip list for each thread
    size_t thread_num = input->thread_num;
    size_t list_length = str_header->length;
    size_t i, j;
    size_t cut = list_length / thread_num;
    pStrHeader str_new_header;

    (*output) = (pIPList_Thread)malloc(sizeof(IPList_Thread));
    if (!(*output))
    {
        ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }
    pIPList_Thread ip_new_node = (*output);

    // the list is too short to split for each thread
    // so just use the whole list for all the threads
    if (cut < 1)
    {
        WarningMessage("The IP list did NOT need the split");

        for (i = 0; i < thread_num; i++)
        {
            str_new_header = str_header;
            ip_new_node->list = str_new_header;
            ip_new_node->next = (pIPList_Thread)malloc(sizeof(IPList_Thread));
            if (!ip_new_node)
            {
                ErrorMessage("malloc failed: %s(%d)", strerror(errno), errno);
                return (size_t)-1;
            }
            ip_new_node->next = (pIPList_Thread)malloc(sizeof(IPList_Thread));
            ip_new_node = ip_new_node->next;
        }

        return sizeof(*output);
    }

    pStrNode tmp_node = str_header->next;
    pStrNode next_tmp_node;
    // deal with the data except the last one
    for (i = 0; i < thread_num - 1; i++)
    {
        str_new_header = (pStrHeader)malloc(sizeof(StrHeader));
        str_new_header->next = tmp_node;
        str_new_header->length = 0;

        // move the tmp_node to the right position
        for (j = 0; j < cut; j++)
        {
            tmp_node = tmp_node->next;
            ++(str_new_header->length);
        }
        // use the next_tmp_node as the bridge
        next_tmp_node = tmp_node->next;
        // cut the node
        tmp_node->next = NULL;
        tmp_node = next_tmp_node;

        ip_new_node->list = str_new_header;
        ip_new_node->next = (pIPList_Thread)malloc(sizeof(IPList_Thread));
        ip_new_node = ip_new_node->next;
    }

    // deal with the last one's data
    str_new_header = (pStrHeader)malloc(sizeof(StrHeader));
    str_new_header->next = tmp_node;
    str_new_header->length = 0;

    while (tmp_node)
    {
        tmp_node = tmp_node->next;
        ++(str_new_header->length);
    }
    ip_new_node->list = str_new_header;
    ip_new_node->next = NULL;

    return sizeof(*output);
}

void FreeIPListBuff(pIPList_Thread input)
{
    // free the buff
    pIPList_Thread tmp = input;
    if (tmp->next)
    {
        FreeIPListBuff(tmp->next);
    }
    free(tmp->list);
    free(tmp);
}

/*
int main(int argc, char *argv[])
{
    // for test
    if (argc == 1)
    {
        return 0;
    }

    // test the SplitUrl work
    if (strcmp(argv[1], "--spliturl-test") == 0)
    {
        pSplitUrlRet output;
        SplitUrl(argv[2], &output);
        if (output->protocol)
        {
            printf("%s\n", output->protocol);
        }
        if (output->host)
        {
            printf("%s\n", output->host);
        }
        printf("%d\n", output->port);
        if (output->suffix)
        {
            printf("%s\n", output->suffix);
        }
        FreeSplitUrlBuff(output);
    }

    return 0;
}
*/
