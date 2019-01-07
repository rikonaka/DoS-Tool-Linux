#define HTTP_POST "POST /%s HTTP/1.1\r\n"                              \
                  "HOST: %s:%d\r\n"                                    \
                  "Accept: */*\r\n"                                    \
                  "Content-Type:application/x-www-form-urlencoded\r\n" \
                  "Content-Length: %lu\r\n\r\n"                        \
                  "%s"