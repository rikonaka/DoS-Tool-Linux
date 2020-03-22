#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

// https
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "../main.h"

#define HTTP 0
#define HTTPS 1

/* from debug.c */
extern size_t ShowMessage(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern size_t InfoMessage(const char *fmt, ...);
extern size_t DebugMessage(const char *fmtsring, ...);
extern size_t ErrorMessage(const char *fmt, ...);

/* from str.c */
extern pSplitUrlOutput *SplitUrl(const char *url, pSplitUrlOutput *output);
extern void FreeSplitUrlBuff(char *host, char *suffix);

/* for the TCPSend and TCPRecv use */
//SSL *GLOBAL_SSL;

int ServerTcpCreateSocket(int port)
{

    /*
     * this function only use in the test module
     */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    int listen_socket;
    int enable = 1;

    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_socket == -1)
    {
        ErrorMessage("server create socket failed: %s(%d)", strerror(errno), errno);
        if (errno == 1)
        {
            DebugMessage("this program should run as root user!");
        }
        else if (errno == 24)
        {
            DebugMessage("you shoud check max file number use 'ulimit -n' in linux.");
            DebugMessage("and change the max file number use 'ulimit -n <setting number>'.");
        }
        return -1;
    }

    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)))
    {
        ErrorMessage("server setsockopt SO_REUSEADDR failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    
    int ret = bind(listen_socket, (struct sockaddr *)&addr, sizeof(addr));
    if(ret == -1)
    {
        ErrorMessage("server bind failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    
    /* only wait for one connection */
    ret = listen(listen_socket, 1);
    if(ret == -1)
    {
        ErrorMessage("server listen failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    
    return listen_socket;
}

size_t WaitClient(int listen_socket)
{
    /*
     * this function only use in the test module
     */

    struct sockaddr_in cliaddr;
    int addrlen = sizeof(cliaddr);
    InfoMessage('waitting connection...');
    int client_socket = accept(listen_socket, (struct sockaddr *)&cliaddr, &addrlen);
    if (client_socket == -1)
    {
        ErrorMessage("get client socket failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }
    
    InfoMessage("client connected: %s", inet_ntoa(cliaddr.sin_addr));
    
    return client_socket;
}

static int ClientTcpCreateSocket(const char *host, int port)
{

    //struct hostent *he;
    struct sockaddr_in server_addr;
    int connect_socket;
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

    connect_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (connect_socket == -1)
    {
        ErrorMessage("client create socket failed: %s(%d)", strerror(errno), errno);
        if (errno == 1)
        {
            DebugMessage("this program should run as root user!");
        }
        else if (errno == 24)
        {
            DebugMessage("you shoud check max file number use 'ulimit -n' in linux.");
            DebugMessage("and change the max file number use 'ulimit -n <setting number>'.");
        }
        return -1;
    }

    if (setsockopt(connect_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)))
    {
        ErrorMessage("client setsockopt SO_REUSEADDR failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    if (setsockopt(connect_socket, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(struct timeval)))
    {
        ErrorMessage("client setsockopt SO_RCVTIMEO failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    if (connect(connect_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        close(connect_socket);
        ErrorMessage("client connect to host failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    return connect_socket;
}

static ssize_t TcpSend(const int socket, const char *buff, int label, SSL *ssl)
{
    /*
     * in this function
     * 'socket' is the socket object to host
     * 'buff' is we want to sending to host string 
     * 'buff_size' is sizeof(buff)
     * 'label' if use the http set 0
     *        else set 1 (like https)
     * 
     * return sended data size
     */

    ssize_t sent_total_size = 0;
    ssize_t ret = 0;
    size_t buff_size = sizeof(buff);

    // make sure the program had sending all data
    if (label == HTTP)
    {
        // http send
        while (sent_total_size < buff_size)
        {
            ret = send(socket, buff + sent_total_size, buff_size - sent_total_size, 0);
            if (ret == -1)
            {
                ErrorMessage("tcp send data failed: %s(%d)", strerror(errno), errno);
                return (size_t)-1;
            }
            sent_total_size += ret;
        }
    }
    else if (label == HTTPS)
    {
        while (sent_total_size < buff_size)
        {
            ret = SSL_write(ssl, buff, buff_size);
            if (ret <= 0)
            {
                ErrorMessage("tcp send via ssl send data failed: %d", SSL_get_error(ssl, ret));
                return (size_t)-1;
            }
            sent_total_size += ret;
        }
    }
    else
    {
        ErrorMessage("tcp send had a wrong label!");
        return (size_t)-1;
    }

    // function will return the sizeof send data bytes
    return sent_total_size;
}

static ssize_t TcpRecv(int socket, char **rebuff, int label, SSL *ssl)
{
    /*
     * This function will return the receive data length
     * if 'flag' is 0, use the http
     *           else set 1, use the https
     */

    ssize_t recv_total_size = 0;
    ssize_t ret = 0;
    char *buff = (char *)malloc(RECEIVE_DATA_SIZE);
    if (label == HTTP)
    {
        for (;;)
        {
            ret = recv(socket, buff, RECEIVE_DATA_SIZE, 0);
            if (ret == -1)
            {
                ErrorMessage("tcp recv data failed");
                return (ssize_t)-1;
            }
            else if (ret == 0)
            {
                // all data recv
                break;
            }

            buff = (char *)realloc(buff, sizeof(buff) + RECEIVE_DATA_SIZE);
            if (!buff)
            {
                ErrorMessage("tcp recv realloc failed: %s(%d)", strerror(errno), errno);
                return (ssize_t)-1;
            }
            recv_total_size += ret;
        }
    }
    else if (label == HTTPS)
    {
        for (;;)
        {
            ret = SSL_read(ssl, buff, RECEIVE_DATA_SIZE);
            if (ret <= 0)
            {
                ErrorMessage("tcp recv data failed: %d", SSL_get_error(ssl, ret));
                return (ssize_t)-1;
            }

            buff = realloc(buff, RECEIVE_DATA_SIZE);
            if (!buff)
            {
                ErrorMessage("tcp recv via https realloc failed: %s(%d)", strerror(errno), errno);
                return (ssize_t)-1;
            }
            recv_total_size += ret;
        }
    }

    //DisplayInfo("%s", buff);
    *rebuff = buff;
    return recv_total_size;
}

static void TcpConnectClose(int socket)
{
    //shutdown(socket, SHUT_RDWR);
    close(socket);
}

size_t HttpMethod(const char *url, const char *request, char **response, int debug_level)
{
    /*
     * use the HTTPMethod post method post 'request_data',
     * then, return the response_data size.
     */

    ShowMessage(VERBOSE, debug_level, "enter HttpMethod function in https.c");

    int socket;
    pSplitUrlOutput sp;

    /* here use 5 * MAX_POST_DATA_LENGTH make sure the sprintf have the enough space */
    if ((strlen(url) == 0) || (strlen(request) == 0))
    {
        ErrorMessage("url or request can not be null!");
        return (size_t)-1;
    }
    if (SplitUrl(url, &sp) == -1)
    {
        ErrorMessage("split url failed!");
        return (size_t)-1;
    }

    ShowMessage(DEBUG, debug_level, "host_addr: %s suffix:%s port:%d", sp->host, sp->suffix, sp->port);
    /* 1 connect */
    socket = ClientTcpCreateSocket(sp->host, sp->port);
    if (socket == -1)
    {
        ErrorMessage("tcp connection create failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    /* 2 send */
    ShowMessage(VERBOSE, debug_level, "Sending data...");
    if (TcpSend(socket, request, HTTP, NULL) == -1)
    {
        ErrorMessage("tcp send data failed: %s(%d)", strerror(errno), errno);
        //return (size_t)-1;
    }

    /* 3 recv */
    ShowMessage(VERBOSE, debug_level, "Recvevicing data...");
    if (TcpRecv(socket, response, HTTP, NULL) == -1)
    {
        ErrorMessage("tcp recvive data failed: %s(%d)", strerror(errno), errno);
        //return (size_t)-1;
    }
    ShowMessage(DEBUG, debug_level, "http recv data: %s", response);

    /* 4 close */
    TcpConnectClose(socket);
    ShowMessage(VERBOSE, debug_level, "exit HttpMethod function in https.c");

    return strlen(*response);
}

static size_t InitCtx(SSL_CTX **output)
{
    const SSL_METHOD *method;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_client_method();
    (*output) = SSL_CTX_new(method);
    if (!(*output))
    {
        ErrorMessage("InitCTX failed: %s(%d)", strerror(errno), errno);
        ERR_print_errors_fp(stderr);
        return (size_t)-1;
    }
    return sizeof(*output);
}

static size_t ShowCerts(SSL *ssl, int debug_level)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        ShowMessage(DEBUG, debug_level, "server certificates:");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        ShowMessage(DEBUG, debug_level, "subject: %s", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        ShowMessage(DEBUG, debug_level, "issuer: %s", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        ErrorMessage("no certificates found!");
        return (size_t)-1;
    }
    return (size_t)0;
}

size_t HttpsMethod(const char *url, const char *request, char **response, int debug_level)
{
    /*
     * use the https method post 'request'.
     * if successd, return the response_data size.
     * if failed, return -1.
     */

    ShowMessage(VERBOSE, debug_level, "Enter HttpsMethod");

    int socket;
    pSplitUrlOutput sp;
    SSL_CTX *ctx;
    SSL *ssl;

    if ((strlen(url) == 0 )|| (strlen(request) == 0))
    {
        ErrorMessage("url or request can not be null!");
        return (size_t)-1;
    }
    if (SplitUrl(url, &sp) == -1)
    {
        ErrorMessage("Process url failed!");
        return (size_t)-1;
    }

    // 1 ssl init
    if (InitCtx(&ctx) == -1)
    {
        ErrorMessage("InitCTX failed");
        return (size_t)-1;
    }

    ShowMessage(DEBUG, debug_level, "host_addr: %s suffix:%s port:%d", sp->host, sp->suffix, sp->port);
    // 2 connect
    socket = ClientTcpCreateSocket(sp->host, sp->port);
    if (socket == -1)
    {
        ErrorMessage("tcp Connection create failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }

    // 3 add ssl
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket);
    if (SSL_connect(ssl) < 0)
    {
        ErrorMessage("HTTPSMethod SSL_connect failed: %s(%d)", strerror(errno), errno);
        //ERR_print_errors_fp(stderr);
        return (size_t)-1;
    }
    // use the global value
    //GLOBAL_SSL = ssl;

    ShowMessage(INFO, debug_level, "Connect with %s encryption", SSL_get_cipher(ssl));
    if (ShowCerts(ssl, debug_level))
    {
        // failed
        ErrorMessage("ShowCert failed!");
        return (size_t)-1;
    }

    // 4 send
    ShowMessage(VERBOSE, debug_level, "Sending data...");
    if (!TcpSend(socket, request, HTTPS, ssl))
    {
        ErrorMessage("Tcp send failed: %s(%d)", strerror(errno), errno);
        return (size_t)NULL;
    }

    // 5 recv
    ShowMessage(VERBOSE, debug_level, "Recvevicing data...");
    if (!TcpRecv(socket, response, HTTPS, ssl))
    {
        ErrorMessage("Tcp receive failed: %s(%d)", strerror(errno), errno);
        return (size_t)NULL;
    }
    ShowMessage(DEBUG, debug_level, "Data: %s", response);

    // 6 close
    TcpConnectClose(socket);
    SSL_CTX_free(ctx);

    ShowMessage(VERBOSE, debug_level, "Exit HttpPostMethod");
    return strlen(*response);
}
