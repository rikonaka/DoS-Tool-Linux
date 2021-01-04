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

    #ifdef DEBUG
    if(listen_socket == -1)
    {
        ErrorMessage("server create socket failed: %s(%d)", strerror(errno), errno);
        if (errno == 1)
        {
            WarningMessage("this program should run as root user!");
        }
        else if (errno == 24)
        {
            WarningMessage("you shoud check max file number use 'ulimit -n' in linux.");
            WarningMessage("and change the max file number use 'ulimit -n <setting number>'.");
        }
        return -1;
    }
    #endif

    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)))
    {
        ErrorMessage("server setsockopt SO_REUSEADDR failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    
    int ret = bind(listen_socket, (struct sockaddr *)&addr, sizeof(addr));

    #ifdef DEBUG
    if(ret == -1)
    {
        ErrorMessage("server bind failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif
    
    /* only wait for one connection */
    ret = listen(listen_socket, 1);

    #ifdef DEBUG
    if(ret == -1)
    {
        ErrorMessage("server listen failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #endif
    
    return listen_socket;
}

size_t WaitClient(int listen_socket)
{
    /*
     * this function only use in the test module
     */

    struct sockaddr_in cliaddr;
    int addrlen = (int)sizeof(cliaddr);
    InfoMessage("waitting connection...");
    int client_socket = accept(listen_socket, (struct sockaddr *)&cliaddr, &addrlen);

    #ifdef DEBUG
    if (client_socket == -1)
    {
        ErrorMessage("get client socket failed: %s(%d)", strerror(errno), errno);
        return (size_t)-1;
    }
    #endif
    
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
    // recv_timeout.tv_sec = RECV_TIME_OUT;
    recv_timeout.tv_sec = 10;
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
            WarningMessage("this program should run as root user!");
        }
        else if (errno == 24)
        {
            WarningMessage("you shoud check max file number use 'ulimit -n' in linux.");
            WarningMessage("and change the max file number use 'ulimit -n <setting number>'.");
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

static size_t TcpSend(const int socket, const char *buff, int label, SSL *ssl)
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

    size_t sent_total_size = 0;
    size_t buff_size = sizeof(buff);
    int ret = 0;

    // make sure the program had sending all data
    if (label == HTTP)
    {
        // http send
        while (sent_total_size < buff_size)
        {
            ret = send(socket, buff + sent_total_size, buff_size - sent_total_size, 0);

            #ifdef DEBUG
            if (ret == -1)
            {
                ErrorMessage("tcp send data failed: %s(%d)", strerror(errno), errno);
                return -1;
            }
            #endif

            sent_total_size += ret;
        }
    }
    else if (label == HTTPS)
    {
        while (sent_total_size < buff_size)
        {
            ret = SSL_write(ssl, buff, buff_size);

            #ifdef DEBUG
            if (ret <= 0)
            {
                ErrorMessage("tcp send via ssl send data failed: %d", SSL_get_error(ssl, ret));
                return -1;
            }
            #endif

            sent_total_size += ret;
        }
    }
    else
    {
        ErrorMessage("tcp send had a wrong label!");
        return -1;
    }

    // function will return the sizeof send data bytes
    return sent_total_size;
}

static size_t TcpRecv(int socket, char **rebuff, int label, SSL *ssl)
{
    /*
     * This function will return the receive data length
     * if 'flag' is 0, use the http
     *           else set 1, use the https
     */

    size_t recv_total_size = 0;
    size_t RECV_BUFF_SIZE = 128; 
    int ret = 0;
    char *buff = (char *)malloc(RECV_BUFF_SIZE);

    if (label == HTTP)
    {
        for (;;)
        {
            ret = recv(socket, buff, RECV_BUFF_SIZE, 0);
            if (ret == -1)
            {
                #ifdef DEBUG
                ErrorMessage("tcp recv data failed");
                #endif

                return -1;
            }
            else if (ret == 0)
            {
                // all data recv
                break;
            }

            buff = (char *)realloc(buff, sizeof(buff) + RECV_BUFF_SIZE);

            #ifdef DEBUG
            if (!buff)
            {
                ErrorMessage("tcp recv realloc failed: %s(%d)", strerror(errno), errno);
                return -1;
            }
            #endif

            recv_total_size += ret;
        }
    }
    else if (label == HTTPS)
    {
        for (;;)
        {
            ret = SSL_read(ssl, buff, RECV_BUFF_SIZE);
            if (ret <= 0)
            {
                #ifdef DEBUG
                ErrorMessage("tcp recv data failed: %d", SSL_get_error(ssl, ret));
                #endif
                return -1;
            }

            buff = realloc(buff, RECV_BUFF_SIZE);

            #ifdef DEBUG
            if (!buff)
            {
                ErrorMessage("tcp recv via https realloc failed: %s(%d)", strerror(errno), errno);
                return -1;
            }
            #endif

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

int HttpMethod(const char *address, const int port, const char *request, char **response)
{

    #ifdef DEBUG
    InfoMessage("enter HttpMethod function in https.c");
    #endif

    int socket;

    if ((strlen(address) == 0) || (strlen(request) == 0))
    {
        ErrorMessage("url or request can not be null!");
        return -1;
    }

    socket = ClientTcpCreateSocket(address, port);
    if (socket == -1)
    {
        ErrorMessage("tcp connection create failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    #ifdef DEBUG
    InfoMessage("Sending data...");
    #endif

    if (TcpSend(socket, request, HTTP, NULL) == -1)
    {
        ErrorMessage("tcp send data failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    #ifdef DEBUG
    InfoMessage("Recvevicing data...");
    #endif

    if (TcpRecv(socket, response, HTTP, NULL) == -1)
    {
        ErrorMessage("tcp recvive data failed: %s(%d)", strerror(errno), errno);
        return -1;
    }
    #ifdef DEBUG
    InfoMessage("http recv data: %s", response);
    #endif

    TcpConnectClose(socket);

    #ifdef DEBUG
    InfoMessage("exit HttpMethod function in https.c");
    #endif

    return 0;
}

static int InitCtx(SSL_CTX **output)
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
        return -1;
    }
    return 0;
}

static int ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        #ifdef DEBUG
        InfoMessage("server certificates:");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        InfoMessage("subject: %s", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        InfoMessage("issuer: %s", line);
        free(line);
        X509_free(cert);
        #endif
    }
    else
    {
        ErrorMessage("no certificates found!");
        return -1;
    }
    return 0;
}

int HttpsMethod(const char *address, const int port, const char *request, char **response)
{
    /*
     * use the https method post 'request'.
     * if successd, return the response_data size.
     * if failed, return -1.
     */

    #ifdef DEBUG
    InfoMessage("Enter HttpsMethod");
    #endif

    int socket;
    SSL_CTX *ctx;
    SSL *ssl;

    if ((strlen(address) == 0 )|| (strlen(request) == 0))
    {
        ErrorMessage("url or request can not be null!");
        return -1;
    }

    // 1 ssl init
    if (InitCtx(&ctx) == -1)
    {
        ErrorMessage("InitCTX failed");
        return -1;
    }

    // 2 connect
    socket = ClientTcpCreateSocket(address, port);
    if (socket == -1)
    {
        ErrorMessage("tcp Connection create failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    // 3 add ssl
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket);
    if (SSL_connect(ssl) < 0)
    {
        ErrorMessage("HTTPSMethod SSL_connect failed: %s(%d)", strerror(errno), errno);
        //ERR_print_errors_fp(stderr);
        return -1;
    }
    // use the global value
    //GLOBAL_SSL = ssl;

    #ifdef DEBUG
    InfoMessage("Connect with %s encryption", SSL_get_cipher(ssl));
    if (ShowCerts(ssl))
    {
        // failed
        ErrorMessage("ShowCert failed!");
        return -1;
    }
    #endif

    // 4 send
    #ifdef DEBUG
    InfoMessage("Sending data...");
    #endif

    if (TcpSend(socket, request, HTTPS, ssl) == -1)
    {
        ErrorMessage("Tcp send failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    // 5 recv
    #ifdef DEBUG
    InfoMessage("Recvevicing data...");
    #endif

    if (TcpRecv(socket, response, HTTPS, ssl) == -1)
    {
        ErrorMessage("Tcp receive failed: %s(%d)", strerror(errno), errno);
        return -1;
    }

    #ifdef DEBUG
    InfoMessage("Data: %s", response);
    #endif

    // 6 close
    TcpConnectClose(socket);
    SSL_CTX_free(ctx);

    #ifdef DEBUG
    InfoMessage("Exit HttpPostMethod");
    #endif

    return 0;
}
