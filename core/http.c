#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../main.h"

// from ../core/debug.h
extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);
extern int DisplayInfo(const char *fmtstring, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmtstring, ...);

static int TCPConnectCreate(const char *host, int port)
{
    /* as you see */

    //struct hostent *he;
    struct sockaddr_in server_addr;
    int sock;
    int enable = 1;
    struct timeval recv_timeout;
    recv_timeout.tv_sec = RECV_TIME_OUT;
    recv_timeout.tv_usec = 0;
    //char *host_test = "192.168.1.1";

    //server_addr.sin_addr.s_addr = inet_addr(host_test);
    server_addr.sin_addr.s_addr = inet_addr(host);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    //server_addr.sin_addr = *((struct in_addr *)he->h_addr);
    //server_addr.sin_addr = *((struct in_addr *)he->h_addr_list);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        DisplayError("Init socket failed: %s", strerror(errno));
        return -1;
    }

    /* setsockopt sucess return 0 */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)))
    {
        DisplayError("setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(struct timeval)))
    {
        DisplayError("setsockopt SO_RCVTIMEO failed: %s", strerror(errno));
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        DisplayError("Connect host failed: %s", strerror(errno));
        return -1;
    }

    return sock;
}

static ssize_t TCPSend(const int socket, const char *buff, size_t buff_size)
{
    /*
     * in this function
     * 'socket' is the socket object to host
     * 'buff' is we want to sending to host string 
     * 'size' is sizeof(buff)
     * 
     * return sended data size
     */

    ssize_t sent_total_size = 0;
    ssize_t sent_size = 0;

    /* make sure the program had sending all data */
    while (sent_total_size < buff_size)
    {
        sent_size = send(socket, buff + sent_total_size, buff_size - sent_total_size, 0);
        if (sent_size == -1)
        {
            DisplayError("Tcp send data failed");
            return -1;
        }
        sent_total_size += sent_size;
    }

    // function will return the sizeof send data bytes
    return sent_total_size;
}

static ssize_t TCPRecv(int socket, char **rebuff)
{
    /*
     * This function will return the receive data length
     */

    ssize_t recv_total_size = 0;
    ssize_t recv_size = 0;
    char *buff = (char *)malloc(MAX_RECEIVE_DATA_SIZE);
    for (;;)
    {
        recv_size = recv(socket, buff, MAX_RECEIVE_DATA_SIZE, 0);
        if (recv_size == -1)
        {
            DisplayError("Tcp recv data failed");
            return -1;
        }
        else if (recv_size == 0)
        {
            break;
        }

        buff = (char *)realloc(buff, sizeof(buff) + MAX_RECEIVE_DATA_SIZE);
        recv_total_size += recv_size;
    }

    //DisplayInfo("%s", buff);
    *rebuff = buff;
    return recv_total_size;
}

static int TCPConnectClose(int socket)
{
    //shutdown(socket, SHUT_RDWR);
    close(socket);
    return 0;
}

int FreeHTTPPostMethodBuff(char *p)
{
    free(p);
    return 0;
}

size_t HTTPPostMethod(char **response, const char *url, const char *request, int debug_level)
{
    /*
     * use the HTTP post method post 'request_data'
     * then, return the response_data size
     */

    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Enter HTTPPostMethod");

    // from ../core/str.h
    extern int GetRandomPassword(char *rebuf, const pInput process_result);
    extern int SplitURL(pSplitURLOutput *output, const char *url);
    extern int FreeSplitURLBuff(char *host, char *suffix);

    int sock;
    pSplitURLOutput sp;

    /* here use 5 * MAX_POST_DATA_LENGTH make sure the sprintf have the enough space */

    if (!url || !request)
    {
        DisplayError("url or post_str not find");
        return -1;
    }
    if (SplitURL(&sp, url))
    {
        DisplayError("ProcessURL failed");
        return -1;
    }

    DisplayDebug(DEBUG_LEVEL_2, debug_level, "host_addr: %s suffix:%s port:%d", sp->host, sp->suffix, sp->port);
    /* 1 connect */
    sock = TCPConnectCreate(sp->host, sp->port);
    if (sock < 0)
    {
        DisplayError("TcpConnectCreate failed");
        return -1;
    }

    /* 2 send */
    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Sending data...");
    if (TCPSend(sock, request, strlen(request)) < 0)
    {
        DisplayError("TcpSend failed");
    }

    /* 3 recv */
    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Recvevicing data...");
    if (TCPRecv(sock, response) <= 0)
    {
        DisplayError("TcpRecv failed");
    }
    //DisplayDebug(DEBUG_LEVEL_2, debug_level, "Data: %s", response);

    /* 4 close */
    TCPConnectClose(sock);
    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Exit HttpPostMethod");
    return strlen(*response);
}