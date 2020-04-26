#ifndef _BRUTE_FORCE_H
#define _BRUTE_FORCE_H

//char *FEIXUN_FWR_604H_POST_SUCCESS = "quick_setup1.asp";
char *FEIXUN_FWR_604H_POST_REQUEST = "POST /goform/formLogin HTTP/1.1\r\n"
                                     "Host: %s\r\n"
                                     "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n"
                                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                                     "Accept-Language: en-US,en;q=0.5\r\n"
                                     "Accept-Encoding: gzip, deflate\r\n"
                                     "Referer: %s\r\n"
                                     "Content-Type: application/x-www-form-urlencoded\r\n"
                                     "Content-Length: %ld\r\n"
                                     "Connection: close\r\n"
                                     "Upgrade-Insecure-Requests: 1\r\n\r\n"
                                     "%s";

FEIXUN_FWR_604H_POST_DATA = "Language=Chinese&Language_set=Chinese&username=%s&password=%s&submit=%%E7%%99%%BB%%E5%%BD%%95";

#endif