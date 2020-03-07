#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "../main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmt, ...);
extern int DisplayError(const char *fmt, ...);

void FreeSplitURLBuff(pSplitURLOutput p)
{
    if (p->protocol)
    {
        free(p->protocol);
    }
    if (p->host)
    {
        free(p->host);
    }
    if (p->suffix)
    {
        free(p->suffix);
    }
    if (p)
    {
        free(p);
    }
}

pSplitURLOutput SplitURL(const char *url, pSplitURLOutput *output)
{
    // rewrite this function at 2019-1-10
    // 0         1           2  3
    // http(s)://192.168.1.1:80/index.php
    // 0 - protocol type
    // 1 - host ip address
    // 2 - port
    // 3 - suffix
    int i = 0;
    //size_t url_len = strlen(url);
    (*output) = (pSplitURLOutput)malloc(sizeof(SplitURLOutput));
    char *purl = (char *)malloc(sizeof(char));
    char *ptmp = purl;
    if (!ptmp)
    {
        DisplayError("SplitURL malloc failed: %s(%d)", strerror(errno), errno);
        return (pSplitURLOutput)NULL;
    }
    if (!strcpy(ptmp, url))
    {
        DisplayError("SplitURL strcpy failed: %s(%d)", strerror(errno), errno);
        return (pSplitURLOutput)NULL;
    }
    //      12           3
    // http://192.168.1.1/index.html
    char *first_slash_position = strchr(purl, '/');
    char *second_slash_position;
    char *third_slash_position;
    // if url like http://192.168.1.1:8080/index.html
    char *colon_position;
    char *protocol_buff = (char *)malloc(sizeof(char));
    char *host_buff = (char *)malloc(sizeof(char));
    char *suffix_buff = (char *)malloc(sizeof(char));
    char *port_buff = (char *)malloc(sizeof(char));

    if (first_slash_position)
    {
        second_slash_position = strchr((first_slash_position + 1), '/');
        // there is not allow only one slash in the url
        // like this: 192.168.1.1/index.html is not allowed
        if (!second_slash_position)
        {
            DisplayError("SplitURL found the URL is not complete");
            return (pSplitURLOutput)NULL;
        }
        colon_position = strchr(second_slash_position + 1, ':');
    }
    else
    {
        colon_position = strchr(purl, ':');
        second_slash_position = NULL;
    }

    if (second_slash_position)
    {
        third_slash_position = strchr((second_slash_position + 1), '/');
    }
    else
    {
        third_slash_position = NULL;
    }

    /* not useful
    if (!memset(host_buff, 0, sizeof(char)))
    {
        DisplayError("SplitURL memset failed");
        return (pSplitURLOutput *)NULL;
    }
    if (!memset(suffix_buff, 0, sizeof(char)))
    {
        DisplayError("SplitURL memset failed");
        return (pSplitURLOutput *)NULL;
    }
    if (!memset(port_buff, 0, sizeof(char)))
    {
        DisplayError("SplitURL memset failed");
        return (pSplitURLOutput *)NULL;
    }
    */

    // copy the host to host_buff
    // i first use in this place
    if (second_slash_position)
    {
        ptmp = (second_slash_position + 1);
        i = 0;
        while (*ptmp && ptmp != colon_position && ptmp != third_slash_position)
        {
            host_buff[i] = *ptmp;
            ++i;
            ++ptmp;
        }
        host_buff[i] = '\0';
    }
    else
    {
        if (colon_position)
        {
            i = 0;
            while (*ptmp && ptmp != colon_position)
            {
                host_buff[i] = *ptmp;
                ++i;
                ++ptmp;
            }
        }
        else
        {
            i = 0;
            while (*ptmp)
            {
                host_buff[i] = *ptmp;
                ++i;
                ++ptmp;
            }
        }
        host_buff[i] = '\0';
    }
    // copy end

    // copy the port if existed
    if (colon_position)
    {
        ptmp = (colon_position + 1);
        i = 0;
        while (*ptmp && ptmp != third_slash_position)
        {
            port_buff[i] = *ptmp;
            ++i;
            ++ptmp;
        }
        port_buff[i] = '\0';
    }
    else
    {
        // if the port is not indicate in the URL
        if (strstr(purl, "https"))
        {
            if (!sprintf(port_buff, "%d", HTTPS_PORT_DEFAULT))
            {
                DisplayError("SplitURL sprintf failed");
                return (pSplitURLOutput)NULL;
            }
        }
        else if (strstr(purl, "http"))
        {
            if (!sprintf(port_buff, "%d", HTTP_PORT_DEFAULT))
            {
                DisplayError("SplitURL sprintf failed");
                return (pSplitURLOutput)NULL;
            }
        }
    }
    // copy end

    // filling the protocol here
    if (!memset(protocol_buff, 0, sizeof(char)))
    {
        DisplayError("SplitURL memset failed");
        return (pSplitURLOutput)NULL;
    }

    if (strstr(purl, "https"))
    {

        if (!strcpy(protocol_buff, "https"))
        {
            DisplayError("SplitURL strcpy failed");
            return (pSplitURLOutput)NULL;
        }
    }
    else if (strstr(purl, "http"))
    {
        if (!strcpy(protocol_buff, "http"))
        {
            DisplayError("SplitURL strcpy failed");
            return (pSplitURLOutput)NULL;
        }
    }
    else
    {
        if (!strcpy(protocol_buff, "not_set"))
        {
            DisplayError("SplitURL strcpy failed");
            return (pSplitURLOutput)NULL;
        }
    }
    // end copy

    // copy the suffix to suffix_buff
    if (third_slash_position)
    {
        ptmp = (third_slash_position + 1);
        i = 0;
        while (*ptmp)
        {
            suffix_buff[i] = *ptmp;
            ++i;
            ++ptmp;
        }
        suffix_buff[i] = '\0';
    }
    else
    {
        if (!strcpy(suffix_buff, "not_set"))
        {
            DisplayError("SplitURL strcpy failed");
            return (pSplitURLOutput)NULL;
        }
    }

    // end copy

    (*output)->protocol = protocol_buff;
    (*output)->host = host_buff;
    (*output)->suffix = suffix_buff;
    (*output)->port = atoi(port_buff);

    if (port_buff)
    {
        free(port_buff);
    }
    if (purl)
    {
        free(purl);
    }
    return (*output);
}

void FreeRandomPasswordBuff(char *password)
{
    if (*password)
    {
        free(password);
    }
}

char *GetRandomPassword(char **rebuf, unsigned int seed, const int length)
{
    // generate the random password and return

    char *r_password = (char *)malloc(MAX_PASSWORD_LENGTH);
    if (!r_password)
    {
        DisplayError("GetRandomPassword malloc failed");
        return (char *)NULL;
    }
    if (!memset(r_password, 0, MAX_PASSWORD_LENGTH))
    {
        DisplayError("GetRandomPassword memset failed");
        return (char *)NULL;
    }
    int r_num;
    int i;

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
            if (!sprintf(r_password, "%s%c", r_password, r_num))
            {
                DisplayError("GetRandomPassword sprintf failed");
                return (char *)NULL;
            }
        }
    }
    *rebuf = r_password;
    return (*rebuf);
}

/*
static int TestStringList(const pStrHeader output)
{
    pStrNode p = output->next;
    DisplayInfo("Linked list length: %d", output->length);
    while (p)
    {
        DisplayInfo("%s", p->username);
        p = p->next;
    }
}
*/

void FreeProcessFileBuff(pStrHeader p)
{
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
        DisplayWarning("Free the space error");
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

pStrHeader ProcessGuessAttackFile(const char *path, pStrHeader *output, int flag)
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

    (*output) = (pStrHeader)malloc(sizeof(StrHeader));
    if (!(*output))
    {
        DisplayError("ProcessGuessAttackFile malloc failed");
        return (pStrHeader)NULL;
    }
    pStrNode str_node;
    (*output)->length = 0;
    (*output)->next = NULL;
    char buff[LENGTH + 1];
    char ch;
    size_t str_length = 0;
    size_t count = 0;

    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        DisplayError("Error: Can not open the guess username or password file");
        return (pStrHeader)NULL;
    }
    while (!feof(fp))
    {
        // if stack error, change here
        if (!memset(buff, 0, LENGTH + 1))
        {
            DisplayError("ProcessGuessAttackFile memset failed");
            return (pStrHeader)NULL;
        }
        ch = fgetc(fp);
        while (ch && ch != '\n' && ch != '\r' && !feof(fp))
        {
            if (!sprintf(buff, "%s%c", buff, ch))
            {
                DisplayError("ProcessGuessAttackFile sprintf failed");
                return (pStrHeader)NULL;
            }
            //DisplayInfo("%c", ch);
            ch = fgetc(fp);
        }

        str_length = strlen(buff);
        if (str_length > 0)
        {
            str_node = (pStrNode)malloc(sizeof(StrNode));
            if (!str_node)
            {
                DisplayError("ProcessGuessAttackFile malloc failed");
                return (pStrHeader)NULL;
            }
            str_node->next = (*output)->next;
            (*output)->next = str_node;
            //DisplayInfo("%ld", str_length);
            // make a space for /0
            str_node->str = (char *)malloc(str_length + 1);
            if (!memset(str_node->str, 0, str_length + 1))
            {
                DisplayError("ProcessGuessAttackFile memset failed");
                return (pStrHeader)NULL;
            }
            if (!strncpy(str_node->str, buff, str_length))
            {
                DisplayError("ProcessGuessAttackFile strncpy failed");
                return (pStrHeader)NULL;
            }
            ++((*output)->length);
            ++count;
        }
    }
    if (fclose(fp))
    {
        DisplayError("ProcessGuessAttackFile fclose failed");
        return (pStrHeader)NULL;
    }
    return (*output);
}

static int GetRandomNumForIP(int seed, int *output)
{
    /*
     * Return the random number between 1-255
     */

    // srand is here
    srand((int)time(0) + seed);

    // [a, b] random interger
    // [1, 254] except space[32]
    // 252 = 254 - 1 - 1
    *output = 1 + (int)(rand() % 252);
    return (*output);
}

void FreeRandomIPBuff(char *p)
{
    if (p)
    {
        free(p);
    }
}

char *GetRandomIP(char **output)
{
    /*
     * Return the random ip address
     */

    int i;
    int random_num = 0;
    // 012345678901234
    // 255.255.255.255
    (*output) = (char *)malloc(IP_BUFFER_SIZE);
    if (!(*output))
    {
        DisplayError("GetRandomIP malloc failed: %s(%d)", strerror(errno), errno);
        return (char *)NULL;
    }
    if (!memset((*output), 0, IP_BUFFER_SIZE))
    {
        DisplayError("GetRandomIP memset failed: %s(%d)", strerror(errno), errno);
        return (char *)NULL;
    }
    char *random_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!random_ip)
    {
        DisplayError("GetRandomIP malloc failed: %s(%d)", strerror(errno), errno);
        return (char *)NULL;
    }
    if (!memset(random_ip, 0, IP_BUFFER_SIZE))
    {
        DisplayError("GetRandomIP memset failed: %s(%d)", strerror(errno), errno);
        return (char *)NULL;
    }

    // 1   2   3 4
    // 192.168.1.1
    for (i = 0; i < 4; i++)
    {
        // ip has four num like 192 168 1 1
        GetRandomNumForIP(i, &random_num);
        if (!sprintf(random_ip, "%s.%d", random_ip, random_num))
        {
            DisplayError("GetRandomIP sprintf failed: %s(%d)", strerror(errno), errno);
            return (char *)NULL;
        }
    }

    // delete the first character '.'
    char *delete = random_ip + 1;
    if (!strncpy((*output), delete, strlen(delete)))
    {
        DisplayError("GetRandomIP strncpy failed: %s(%d)", strerror(errno), errno);
        return (char *)NULL;
    }
    free(random_ip);
    return (*output);
}

size_t GetRandomPort(size_t *output)
{
    // Return randome port from 1 to 9999

    int random_number = -1;

    // srand is here
    srand((int)time(0));

    // [a, b] random interger
    // [1, 9999] except space[32]
    // 9997 = 9999 - 1 - 1
    random_number = 1 + (int)(rand() % 9997);
    *output = random_number;
    return (*output);
}

int LocateStrNodeElement(const pStrHeader p, pStrNode *element, const size_t loc)
{
    // locate the str linked list element
    if (loc < 0 || loc > p->length)
    {
        DisplayError("LocateStrNodeElement loc illegal");
        return 1;
    }
    size_t count = 0;
    pStrNode t = p->next;
    while (count != loc)
    {
        t = t->next;
        ++count;
    }

    *element = t;
    return 0;
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
        DisplayWarning("Free the space error");
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

pStrHeader ProcessACKIPListFile(pStrHeader *output)
{
    // return NULL = failed
    // return something = success

    (*output) = (pStrHeader)malloc(sizeof(StrHeader));
    if (!(*output))
    {
        DisplayError("ProcessACKIPListFile malloc failed");
        return (pStrHeader)NULL;
    }

    pStrNode str_node;
    (*output)->length = 0;
    (*output)->next = NULL;
    char *buff = (char *)malloc(IP_BUFFER_SIZE);
    char ch;
    size_t str_length = 0;
    size_t count = 0;

    // the file path and file name is default here
    FILE *fp = fopen(ACK_IP_LIST_NAME, "r");
    if (!fp)
    {
        DisplayError("Error: Can not open the ack ip list file");
        DisplayError("%s(%d)", strerror(errno), errno);
        return (pStrHeader)NULL;
    }

    while (!feof(fp))
    {
        // if stack error, change here
        if (!memset(buff, 0, IP_BUFFER_SIZE))
        {
            DisplayError("ProcessACKIPListFile memset failed");
            return (pStrHeader)NULL;
        }

        ch = fgetc(fp);
        while (ch && ch != '\n' && ch != '\r' && !feof(fp))
        {
            if (!sprintf(buff, "%s%c", buff, ch))
            {
                DisplayError("ProcessACKIPListFile sprintf failed");
                return (pStrHeader)NULL;
            }
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
                DisplayError("ProcessACKIPLIstFile malloc failed");
                return (pStrHeader)NULL;
            }
            str_node->next = (*output)->next;
            (*output)->next = str_node;
            // make a space for /0
            str_node->str = (char *)malloc(str_length + 1);
            if (!memset(str_node->str, 0, str_length + 1))
            {
                DisplayError("ProcessACKIPListFile memset failed");
                return (pStrHeader)NULL;
            }
            if (!memcpy(str_node->str, buff, str_length + 1))
            {
                DisplayError("ProcessACKIPListFile strncpy failed");
                return (pStrHeader)NULL;
            }
            // init the node lock as 0
            ++((*output)->length);
            ++count;
        }
    }
    if (fclose(fp))
    {
        DisplayError("ProcessACKIPListFile fclose failed");
        return (pStrHeader)NULL;
    }
    free(buff);
    return (*output);
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
        DisplayWarning("Free the space error");
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

pStrHeader ProcessDNSIPListFile(pStrHeader *output)
{
    // return NULL = failed
    // return something = success

    (*output) = (pStrHeader)malloc(sizeof(StrHeader));
    if (!(*output))
    {
        DisplayError("ProcessDNSIPListFile malloc failed");
        return (pStrHeader)NULL;
    }

    pStrNode str_node;
    (*output)->length = 0;
    (*output)->next = NULL;
    char *buff = (char *)malloc(IP_BUFFER_SIZE);
    char ch;
    size_t str_length = 0;
    size_t count = 0;

    // the file path and file name is default here
    FILE *fp = fopen(DNS_IP_LIST_NAME, "r");
    if (!fp)
    {
        DisplayError("Error: Can not open the ack ip list file");
        DisplayError("%s(%d)", strerror(errno), errno);
        return (pStrHeader)NULL;
    }

    while (!feof(fp))
    {
        // if stack error, change here
        if (!memset(buff, 0, IP_BUFFER_SIZE))
        {
            DisplayError("ProcessDNSIPListFile memset failed");
            return (pStrHeader)NULL;
        }

        ch = fgetc(fp);
        while (ch && ch != '\n' && ch != '\r' && !feof(fp))
        {
            if (!sprintf(buff, "%s%c", buff, ch))
            {
                DisplayError("ProcessDNSIPListFile sprintf failed");
                return (pStrHeader)NULL;
            }
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
                DisplayError("ProcessDNSIPLIstFile malloc failed");
                return (pStrHeader)NULL;
            }
            str_node->next = (*output)->next;
            (*output)->next = str_node;
            // make a space for /0
            str_node->str = (char *)malloc(str_length + 1);
            if (!memset(str_node->str, 0, str_length + 1))
            {
                DisplayError("ProcessDNSIPListFile memset failed");
                return (pStrHeader)NULL;
            }
            if (!memcpy(str_node->str, buff, str_length + 1))
            {
                DisplayError("ProcessDNSIPListFile strncpy failed");
                return (pStrHeader)NULL;
            }
            // init the node lock as 0
            ++((*output)->length);
            ++count;
        }
    }
    if (fclose(fp))
    {
        DisplayError("ProcessDNSIPListFile fclose failed");
        return (pStrHeader)NULL;
    }
    free(buff);
    return (*output);
}

void ProcessACKIPListFileTest(void)
{
    DisplayInfo("Enter ProcessACKIPLIstFileTest");
    pStrHeader header;
    ProcessACKIPListFile(&header);
    //DisplayInfo(">>> 2 <<<");
    DisplayInfo("Length: %ld", header->length);
    //printf("%ld", header->length);
    pStrNode node = header->next;
    while (node)
    {
        DisplayInfo("Value: %s", node->str);
        node = node->next;
    }

    FreeProcessACKIPListBuff(header);
}

pIPList_Thread SplitIPForThread(pIPList_Thread *output, const pInput input, const pStrHeader str_header)
{
    // split the whole ip list for each thread
    size_t thread_num = input->max_thread;
    size_t list_length = str_header->length;
    size_t i, j;
    size_t cut = list_length / thread_num;
    pStrHeader str_new_header;

    (*output) = (pIPList_Thread)malloc(sizeof(IPList_Thread));
    if (!(*output))
    {
        DisplayError("SplitIPForThread malloc failed: %s(%d)", strerror(errno), errno);
        return (pIPList_Thread)NULL;
    }
    pIPList_Thread ip_new_node = (*output);

    // the list is too short to split for each thread
    // so just use the whole list for all the threads
    if (cut < 1)
    {
        DisplayWarning("The IP list did NOT need the split");

        for (i = 0; i < thread_num; i++)
        {
            str_new_header = str_header;
            ip_new_node->list = str_new_header;
            ip_new_node->next = (pIPList_Thread)malloc(sizeof(IPList_Thread));
            if (!ip_new_node)
            {
                DisplayError("SplitIPForThread malloc failed: %s(%d)", strerror(errno), errno);
                return (pIPList_Thread)NULL;
            }
            ip_new_node->next = (pIPList_Thread)malloc(sizeof(IPList_Thread));
            ip_new_node = ip_new_node->next;
        }

        return (*output);
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

    return (*output);
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

    // test the SplitURL work
    if (strcmp(argv[1], "--spliturl-test") == 0)
    {
        pSplitURLOutput output;
        SplitURL(argv[2], &output);
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
        FreeSplitURLBuff(output);
    }

    return 0;
}
*/