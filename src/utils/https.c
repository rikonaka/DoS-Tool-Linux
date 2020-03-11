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

#define HTTP_LABEL 0
#define HTTPS_LABEL 1

/* from debug.c */
extern int ShowMessage(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int InfoMessage(const char *fmt, ...);
extern int DebugMessage(const char *fmtsring, ...);
extern int ErrorMessage(const char *fmt, ...);

/* from str.c */
extern pSplitUrlOutput *SplitUrl(const char *url, pSplitUrlOutput *output);
extern void FreeSplitUrlBuff(char *host, char *suffix);

/* for the TCPSend and TCPRecv use */
SSL *GLOBAL_SSL;

static int TcpConnectionCreate(const char *host, int port)
{

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

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        ErrorMessage("Create socket failed: %s(%d)", strerror(errno), errno);
        if (errno == 1)
        {
            DebugMessage("This program should run as root user!");
        }
        else if (errno == 24)
        {
            DebugMessage("You shoud check max file number use 'ulimit -n' in linux.");
            DebugMessage("And change the max file number use 'ulimit -n <setting number>'.");
        }
        return 0;
    }

    /* setsockopt sucess return 0 */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)))
    {
        ErrorMessage("setsockopt SO_REUSEADDR failed: %s(%d)", strerror(errno), errno);
        return 0;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(struct timeval)))
    {
        ErrorMessage("setsockopt SO_RCVTIMEO failed: %s(%d)", strerror(errno), errno);
        return 0;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        close(sock);
        ErrorMessage("Connect host failed: %s(%d)", strerror(errno), errno);
        return 0;
    }

    return sock;
}

static ssize_t TcpSend(const int socket, const char *buff, int label)
{
    /*
     * in this function
     * 'socket' is the socket object to host
     * 'buff' is we want to sending to host string 
     * 'buff_size' is sizeof(buff)
     * 'flag' if use the http set 0
     *        else set 1 (like https)
     * 
     * return sended data size
     */

    ssize_t sent_total_size = 0;
    ssize_t sent_size = 0;
    size_t buff_size = sizeof(buff);

    // make sure the program had sending all data
    if (label == HTTP_LABEL)
    {
        // http send
        while (sent_total_size < buff_size)
        {
            sent_size = send(socket, buff + sent_total_size, buff_size - sent_total_size, 0);
            if (sent_size < 0)
            {
                ErrorMessage("Tcp send data failed: %s(%d)", strerror(errno), errno);
                return (size_t)NULL;
            }
            sent_total_size += sent_size;
        }
    }
    else if (label == HTTPS_LABEL)
    {
        while (sent_total_size < buff_size)
        {
            sent_size = SSL_write(GLOBAL_SSL, buff, buff_size);
            if (sent_size < 0)
            {
                ErrorMessage("Tcp via ssl send data failed: %s(%d)", strerror(errno), errno);
                return (size_t)NULL;
            }
            sent_total_size += sent_size;
        }
    }
    else
    {
        ErrorMessage("Tcp send flag set wrong");
        return (size_t)NULL;
    }

    // function will return the sizeof send data bytes
    return sent_total_size;
}

static ssize_t TcpRecv(int socket, char **rebuff, int label)
{
    /*
     * This function will return the receive data length
     * if 'flag' is 0, use the http
     *           else set 1, use the https
     */

    ssize_t recv_total_size = 0;
    ssize_t recv_size = 0;
    char *buff = (char *)malloc(RECEIVE_DATA_SIZE);
    if (label == HTTP_LABEL)
    {
        for (;;)
        {
            recv_size = recv(socket, buff, RECEIVE_DATA_SIZE, 0);
            if (recv_size < 0)
            {
                ErrorMessage("Tcp receive data failed");
                return (ssize_t)NULL;
            }
            else if (recv_size == 0)
            {
                // all data recv
                break;
            }

            buff = (char *)realloc(buff, sizeof(buff) + RECEIVE_DATA_SIZE);
            if (!buff)
            {
                ErrorMessage("Realloc failed: %s(%d)", strerror(errno), errno);
                return (ssize_t)NULL;
            }
            recv_total_size += recv_size;
        }
    }
    else if (label == HTTPS_LABEL)
    {
        for (;;)
        {
            recv_size = SSL_read(GLOBAL_SSL, buff, RECEIVE_DATA_SIZE);
            if (recv_size < 0)
            {
                ErrorMessage("Tcp receive via https receive data failed: %s(%d)", strerror(errno), errno);
                return (ssize_t)NULL;
            }
            else if (recv_size == 0)
            {
                break;
            }

            buff = realloc(buff, RECEIVE_DATA_SIZE);
            if (!buff)
            {
                ErrorMessage("Tcp receive via https realloc failed: %s(%d)", strerror(errno), errno);
                return (ssize_t)NULL;
            }
            recv_total_size += recv_size;
        }
    }

    //DisplayInfo("%s", buff);
    *rebuff = buff;
    return recv_total_size;
}

static int TcpConnectClose(int socket)
{
    //shutdown(socket, SHUT_RDWR);
    close(socket);
    return 0;
}

size_t HttpMethod(const char *url, const char *request, char **response, int debug_level)
{
    /*
     * use the HTTPMethod post method post 'request_data',
     * then, return the response_data size.
     */

    ShowMessage(VERBOSE, debug_level, "Enter HttpMethod function in https.c");

    int sock;
    pSplitUrlOutput sp;

    /* here use 5 * MAX_POST_DATA_LENGTH make sure the sprintf have the enough space */
    if (!url || !request)
    {
        ErrorMessage("url or post_str not find!");
        return (size_t)NULL;
    }
    if (SplitUrl(url, &sp))
    {
        ErrorMessage("Process url failed!");
        return (size_t)NULL;
    }

    ShowMessage(DEBUG, debug_level, "host_addr: %s suffix:%s port:%d", sp->host, sp->suffix, sp->port);
    /* 1 connect */
    sock = TcpConnectionCreate(sp->host, sp->port);
    if (!sock)
    {
        ErrorMessage("Tcp connection create failed: %s(%d)", strerror(errno), errno);
        return (size_t)NULL;
    }

    /* 2 send */
    ShowMessage(VERBOSE, debug_level, "Sending data...");
    if (!TcpSend(sock, request, HTTP_LABEL))
    {
        ErrorMessage("Tcp send data failed: %s(%d)", strerror(errno), errno);
    }

    /* 3 recv */
    ShowMessage(VERBOSE, debug_level, "Recvevicing data...");
    if (!TcpRecv(sock, response, HTTP_LABEL))
    {
        ErrorMessage("Tcp recvive data failed: %s(%d)", strerror(errno), errno);
    }
    ShowMessage(DEBUG, debug_level, "Data: %s", response);

    /* 4 close */
    TcpConnectClose(sock);
    ShowMessage(VERBOSE, debug_level, "Exit HttpMethod function in https.c");

    return strlen(*response);
}

/* HTTPSMethod blow */
static SSL_CTX *InitCtx(SSL_CTX **output)
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
        return (SSL_CTX *)NULL;
    }
    return (*output);
}

static int ShowCerts(SSL *ssl, int debug_level)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        ShowMessage(DEBUG, debug_level, "Server certificates:");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        ShowMessage(DEBUG, debug_level, "Subject: %s", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        ShowMessage(DEBUG, debug_level, "Issuer: %s", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        ErrorMessage("ShowCerts no certificates found");
        return 1;
    }
    return 0;
}

size_t HttpsMethod(const char *url, const char *request, char **response, int debug_level)
{
    /*
     * use the HTTPs post method post 'request_data',
     * then, return the response_data size.
     */

    ShowMessage(VERBOSE, debug_level, "Enter HttpsMethod");


    int sock;
    pSplitUrlOutput sp;
    SSL_CTX *ctx;
    SSL *ssl;

    /// here use 5 * MAX_POST_DATA_LENGTH make sure the sprintf have the enough space
    if (!url || !request)
    {
        ErrorMessage("url or post_str not find!");
        return (size_t)NULL;
    }
    if (!SplitUrl(url, &sp))
    {
        ErrorMessage("Process url failed!");
        return (size_t)NULL;
    }

    // 1 ssl init
    if (!InitCtx(&ctx))
    {
        ErrorMessage("InitCTX failed");
        return (size_t)NULL;
    }

    ShowMessage(DEBUG, debug_level, "host_addr: %s suffix:%s port:%d", sp->host, sp->suffix, sp->port);
    // 2 connect
    sock = TcpConnectionCreate(sp->host, sp->port);
    if (!sock)
    {
        ErrorMessage("Tcp Connection create failed: %s(%d)", strerror(errno), errno);
        return (size_t)NULL;
    }

    // 3 add ssl
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) < 0)
    {
        ErrorMessage("HTTPSMethod SSL_connect failed: %s(%d)", strerror(errno), errno);
        ERR_print_errors_fp(stderr);
        return (size_t)NULL;
    }
    // use the global value
    GLOBAL_SSL = ssl;

    ShowMessage(INFO, debug_level, "Connect with %s encryption", SSL_get_cipher(ssl));
    if (ShowCerts(ssl, debug_level))
    {
        // failed
        ErrorMessage("ShowCert failed!");
        return (size_t)NULL;
    }

    // 4 send
    ShowMessage(VERBOSE, debug_level, "Sending data...");
    if (!TcpSend(sock, request, HTTPS_LABEL))
    {
        ErrorMessage("Tcp send failed: %s(%d)", strerror(errno), errno);
        return (size_t)NULL;
    }

    // 5 recv
    ShowMessage(VERBOSE, debug_level, "Recvevicing data...");
    if (!TcpRecv(sock, response, HTTPS_LABEL))
    {
        ErrorMessage("Tcp receive failed: %s(%d)", strerror(errno), errno);
        return (size_t)NULL;
    }
    ShowMessage(DEBUG, debug_level, "Data: %s", response);

    // 6 close
    TcpConnectClose(sock);
    SSL_CTX_free(ctx);

    ShowMessage(VERBOSE, debug_level, "Exit HttpPostMethod");
    return strlen(*response);
}
