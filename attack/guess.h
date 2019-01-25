#ifndef _GUESS_H
#define _GUESS_H
#include <stdlib.h>
#include <string.h>

#define CheckModel 0
#define CheckLength 1

#define UHEADER 0
#define PHEADER 1

char *FEIXUN_FWR_604H_REQUEST = "POST /goform/formLogin HTTP/1.1\r\n"
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
char *FEIXUN_FWR_604H_REQUEST_DATA = "Language=Chinese&Language_set=Chinese&username=%s&password=%s&submit=%%E7%%99%%BB%%E5%%BD%%95";
char *FEIXUN_FWR_604H_SUCCESS = "quick_setup1.asp";

char *NEXTCLOUD15_REQUEST = "POST /login HTTP/1.1\r\n"
                            "Host: 192.168.1.156\r\n"
                            "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\n"
                            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                            "Accept-Language: en-US,en;q=0.5\r\n"
                            "Accept-Encoding: gzip, deflate\r\n"
                            "Content-Type: application/x-www-form-urlencoded\r\n"
                            "Content-Length: 178\r\n"
                            "Connection: close\r\n"
                            "Cookie: ocze9anuhxad=8stqukvavp3ks1950hvii1nrja; oc_sessionPassphrase=MjhBYcEZ7%2B9izQ%2BkFLi1gvIyzvrjw2Cauoh8XsjOTMac2uyqiK2Eu5eGttw%2FhFff9aLd%2FLle%2B33vpcX5EcZneSDUvQupbXuz0z2fLPD3KvfAOaV%2BAC3iDpZGFVRpj8a4; __Host-nc_sameSiteCookielax=true; __Host-nc_sameSiteCookiestrict=true\r\n"
                            "Upgrade-Insecure-Requests: 1\r\n";

char *NEXTCLOUD15_REQUEST_DATA = "user=admin&password=test&timezone_offset=8&timezone=Asia%2FShanghai&requesttoken=vS0abBo5YejFPDZQeCsy1D8WrMPtbVsxE2tvIhKNxtE%3D%3A8GpuIn9OIt6XTG8pEh1%2Bv1VDmYSFO25FXydeE3y4r4s%3D";

typedef struct match_output
{
    char *request;
    char *request_data;
    char *success_or_not;
    struct match_output *next;
} MatchOutput, *pMatchOutput;

#endif