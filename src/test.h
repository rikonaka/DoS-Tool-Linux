#ifndef _TEST_H
#define _TEST_H

/* this request is only used as test */
char *TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
                     "Host: 127.0.0.1\r\n"
                     "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n"
                     "Accept: text/html\r\n"
                     "Accept-Language: en-US\r\n"
                     "Accept-Encoding: gzip, deflate\r\n"
                     "Connection: close\r\n";

char *TEST_RESPONSE = "HTTP/1.1 200 OK\r\n"
                      "Date: Sat, 31 Dec 2020 23:59:59 GMT\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: 122\r\n\r\n"
                      "<html>\r\n"
                      "<head>\r\n"
                      "<title>Test Homepage</title>"
                      "</head>\r\n"
                      "<body>\r\n"
                      "<!-- body goes here -->\r\n"
                      "</body>\r\n"
                      "</html>\r\n";

#define LOCAL_PORT 9988
#define LOCAL_ADDRESS "127.0.0.1"

/* from base64.h */
extern size_t Base64Decode(unsigned char **buffer, char *b64message);
extern char *Base64Encode(char **b64message, unsigned char *buffer, size_t length);
extern void FreeBase64Buffer(char *b64message);

/* from https.c */
extern size_t HttpMethod(const char *url, const char *request, char **response, int debug_level);
extern size_t HttpsMethod(const char *url, const char *request, char **response, int debug_level);

extern int ServerTcpCreateSocket(int port);
extern size_t WaitClient(int listen_socket);

#endif