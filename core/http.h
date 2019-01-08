#ifndef _HTTP_H
#define _HTTP_H

#define HTTP_POST_MODEL "POST /%s HTTP/1.1\r\n"                              \
                        "HOST: %s:%d\r\n"                                    \
                        "Accept: */*\r\n"                                    \
                        "Content-Type:application/x-www-form-urlencoded\r\n" \
                        "Content-Length: %lu\r\n\r\n"                        \
                        "%s"

size_t HTTPPostMethod(char **response, const char *url, const char *request, int debug_level);

#endif