#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "http.h"
#include "debug.h"
#include "cstring.h"
#include "../main.h"

static int TcpConnectCreate(const char *host, int port)
{
    /* 
     * create a tcp connect
     * return socket file id
     */

    //struct hostent *he;
    struct sockaddr_in server_addr;
    int sock;
    int send_size = MAX_SEND_DATA_SIZE;
    int enable = 1;
    //char *host_test = "192.168.1.1";

    /*
    if (!(he = gethostbyname(host)))
    {
        return -1;
    }
    */

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
        DisplayError("setsockopt-1 failed: %s", strerror(errno));
        return -1;
    }

    /*
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &send_size, sizeof(send_size)))
    {
        DisplayError("setsockopt-2 failed: %s", strerror(errno));
        return -1;
    }
    */

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        DisplayError("Connect host failed: %s", strerror(errno));
        return -1;
    }

    return sock;
}

static ssize_t TcpSend(const int socket, const char *buff, size_t buff_size)
{
    /*
     * in this function
     * 'socket' is the socket object to host
     * 'buff' is we want to sending to host string 
     * 'size' is sizeof(buff)
     * 
     * return sended data size
     */

    ssize_t sended_data_size = 0;

    /* make sure the program had sending all data */
    // send(sockfd, buf, len, flags);
    sended_data_size = send(socket, buff, buff_size, 0);
    if (sended_data_size == -1)
    {
        DisplayError("Tcp send data failed");
        return -1;
    }

    // function will return the sizeof send data bytes
    return sended_data_size;
}

static ssize_t TcpRecv(int socket, char *rebuf)
{
    /*
     * This function will return the receive string length
     */
    ssize_t recv_data_size = 0;
    //recvnum = recv(socket, lpbuff, BUFFER_SIZE * 4, 0);
    recv_data_size = recv(socket, rebuf, MAX_RECEIVE_DATA_SIZE, 0);
    return recv_data_size;
}

static int TcpConnectClose(int socket)
{
    //shutdown(socket, SHUT_RDWR);
    close(socket);
    return 0;
}

size_t HTTPPostMethod(char **response, const char *url, const char *request, int debug_level)
{
    /*
     * use the HTTP post method post 'request_data'
     * then, return the response_data size
     */

    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Enter HTTPPostMethod");
    int sock;
    int port;
    char *host;
    char *suffix;

    /* here use 5 * MAX_POST_DATA_LENGTH make sure the sprintf have the enough space */
    char receive_buff[MAX_RECEIVE_DATA_SIZE];

    if (!url || !request)
    {
        DisplayError("url or post_str not find");
        return -1;
    }

    if (SplitURL(url, &host, &suffix, &port))
    {
        DisplayError("ProcessURL failed");
        return -1;
    }
    DisplayDebug(DEBUG_LEVEL_1, debug_level, "host_addr: %s file:%s port:%d", host, suffix, port);
    DisplayDebug(DEBUG_LEVEL_2, debug_level, "%s", host);
    sock = TcpConnectCreate(host, port);
    if (sock < 0)
    {
        DisplayError("TcpConnectCreate failed");
        return -1;
    }

    /* 
     * it's time to recv from server
     * store the data from server in 'lpbuf'
     * this will wait and recv data and return
     */

    /* send now */
    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Sending data...");
    if (TcpSend(sock, request, strlen(request)) < 0)
    {
        DisplayError("TcpSend failed");
        //http_tcpclient_close(socket_fd);
        //return return_string;
    }

    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Recvevicing data...");
    if (TcpRecv(sock, receive_buff) <= 0)
    {
        DisplayError("TcpRecv failed");
        //http_tcpclient_close(socket_fd);
        //return return_string;
    }

    *response = receive_buff;
    TcpConnectClose(sock);

    DisplayDebug(DEBUG_LEVEL_3, debug_level, "Exit HttpPostMethod");
    return strlen(receive_buff);
}