#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "http.h"
#include "debug.h"
#include "../main.h"

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
        DisplayError("Init socket failed");
        return 1;
    }

    int flag = 1;
    int len = sizeof(int);
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len);
    if (ret != 0)
    {
        DisplayError("Set ret 1 failed");
        return 1;
    }

    int sendbuf = MAX_SEND_DATA_SIZE;

    ret = setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf));
    if (ret != 0)
    {
        DisplayError("Set ret 2 failed");
        return 1;
    }

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        DisplayError("Connect host failed");
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
            DisplayError("Send failed");
            return -1;
        }
        sent += tmpres;
    }
    // function will return the sizeof send data bytes
    return sent;
}

static int HttpTcpClientRecv(int socket, char *rebuf)
{
    /*
     * This function will return the receive string length
     */
    int recvnum = 0;
    //recvnum = recv(socket, lpbuff, BUFFER_SIZE * 4, 0);
    recvnum = recv(socket, rebuf, MAX_RECEIVE_DATA_SIZE, 0);
    return recvnum;
}

static int HttpTcpClientClose(int socket)
{
    //shutdown(socket, SHUT_RDWR);
    close(socket);
    return 0;
}

int HttpPostMethod(const pAttarckStruct attack_struct, char *rebuf)
{
    DisplayDebug(DEBUG_LEVEL_3, attack_struct->debug_level, "Enter HttpPostMethod");
    int socket_fd;
    int port;
    /* here use 5 * MAX_POST_DATA_LENGTH make sure the sprintf have the enough space */
    char lpbuf[5 * MAX_SEND_DATA_SIZE];
    char host_addr[SMALL_BUFFER_SIZE];
    char file[SMALL_BUFFER_SIZE];
    char http_receive_buf[MAX_RECEIVE_DATA_SIZE];
    char result_buf[MAX_RECEIVE_DATA_SIZE];

    if (!attack_struct->url || !attack_struct->post_data)
    {
        DisplayError("url or post_str not find");
        return 1;
    }

    if (ProcessURL(attack_struct->url, host_addr, file, &port))
    {
        DisplayError("ProcessURL failed");
        return 1;
    }
    DisplayDebug(DEBUG_LEVEL_1, attack_struct->debug_level, "host_addr: %s\nfile:%s\nport:%d\n", host_addr, file, port);
    socket_fd = HttpTcpClientCreate(host_addr, port);
    if (socket_fd < 0)
    {
        DisplayError("HttpTcpClientCreate failed");
        return 1;
    }

    DisplayDebug(DEBUG_LEVEL_2, attack_struct->debug_level, "Send:\n%s\n", lpbuf);
    sprintf(lpbuf, HTTP_POST, file, host_addr, port, strlen(attack_struct->post_data), attack_struct->post_data);

    /* 
     * it's time to recv from server
     * store the data from server in 'lpbuf'
     * this will wait and recv data and return
     */

    /* send now */
    DisplayDebug(DEBUG_LEVEL_3, attack_struct->debug_level, "Start sending data...");
    if (HttpTcpClientSend(socket_fd, lpbuf, strlen(lpbuf)) < 0)
    {
        DisplayError("HttpTcpClientSend failed");
        //http_tcpclient_close(socket_fd);
        //return return_string;
    }

    if (HttpTcpClientRecv(socket_fd, http_receive_buf) <= 0)
    {
        DisplayError("TttpTcpClientRecv failed");
        //http_tcpclient_close(socket_fd);
        //return return_string;
    }
    DisplayDebug(DEBUG_LEVEL_3, attack_struct->debug_level, "Recvevicing the data from server...");

    // Return value is '0' mean success
    if (CheckResult(http_receive_buf, result_buf, attack_struct->debug_level) != 0)
    {
        DisplayWarning("CheckResult not found anything fun");
        //return return_string;
    }
    DisplayDebug(DEBUG_LEVEL_3, attack_struct->debug_level, "Start copying the data to buf...");
    strcpy(rebuf, result_buf);
    DisplayDebug(DEBUG_LEVEL_3, attack_struct->debug_level, "Finish copy...");
    //return response_data;
    //http_tcpclient_close(socket_fd);
    HttpTcpClientClose(socket_fd);
    DisplayDebug(DEBUG_LEVEL_3, attack_struct->debug_level, "Exit HttpPostMethod");
    return 0;
}