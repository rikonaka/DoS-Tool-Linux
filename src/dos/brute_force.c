#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>

#include "../main.h"
#include "../debug.h"

#include "brute_force.h"

static char *StrListDistributor(pStrHeader str_list_header)
{
    /*
     * return a str from str list
     * and set the str label to 1(used)
     */

    if (str_list_header->mode != SPECIAL_STR_LIST_MODE)
    {
        pStrNode cursor = str_list_header->cursor;
        if (cursor->label != 1)
        {
            cursor->label = 1;
            str_list_header->cursor = cursor->next;
        }
        else
        {
            #ifdef DEBUG
            ErrorMessage("distributor error");
            return -1;
            #endif
        }
        

        return cursor->str;
    }
    else
    {
        return str_list_header->next->str;
    }
}

static char *_GetRequestModel(const char *router_type)
{
    if (strcmp(router_type, "feixun_fwr_604h") == 0)
    {
        return FEIXUN_FWR_604H_POST_REQUEST;
    }
    else if (strcmp(router_type, "tplink_test") == 0)
    {
        return TPLINK_TEST_POST_REQUEST;
    }
    
    return NULL;
}

static char *_GetRequestPostDataModel(const char *router_type)
{
    if (strcmp(router_type, "feixun_fwr_604h") == 0)
    {
        return FEIXUN_FWR_604H_POST_DATA;
    }
    else if (strcmp(router_type, "tplink_test") == 0)
    {
        return TPLINK_TEST_POST_DATA;
    }

    return NULL;
}

/*
* #define BRUTE_FORCE_US_PF 1    // username specified (user input or default value) and password from file
* #define BRUTE_FORCE_US_PR 2    // username specified (user input or defalut value) and password from random
* #define BRUTE_FORCE_US_PS 3    // username specified and password also specified
* #define BRUTE_FORCE_UF_PS 4    // username from file and password specified
* #define BRUTE_FORCE_UF_PF 5    // the username and password both from file 
*/

static int _AttackThread(pParameter parameter)
{
    
    pStrHeader password_header = parameter->_brute_force_st->password_list_header;
    pStrHeader username_header = parameter->_brute_force_st->username_list_header;

    char *request_model = _GetRequestModel(parameter->router_type);
    char *request = (char *)malloc(strlen(request_model) * 2); // double space
    char *post_model = _GetRequestPostDataModel(parameter->router_type);
    char *post = (char *)malloc(strlen(post_model) * 2);

    for (;;)
    {
        char *password = StrListDistributor(password_header);
        if (!password)
        {
            break;
        }
        for (;;)
        {
            char *username = StrListDistributor(username_header);
            if (!username)
            {
                break;
            }
            if (parameter->username_encrypt_type != NO_ENCRYPT)
            {
                if (parameter->username_encrypt_type == BASE64_ENCRYPT)
                {
                    //char *base64_username = Base64Encode(username);
                }
            }
            sprintf(post, post_model, username, password);
            sprintf(request, request_model, parameter->target_address, parameter->target_address, post_data_len, post_data)
            if (parameter->address_type == ADDRESS_TYPE_HTTP)
            {
                HttpMethod(parameter->target_address, parameter->target_port, )
            }

        }
    }


    return 0;
}

int StartBruteForceAttack(pParameter parameter)
{
    #ifdef DEBUG
    InfoMessage("Enter StartAttackProcess");
    #endif

    if (!(parameter->router_type) || strlen(parameter->router_type) == 0)
    {
        ErrorMessage("please specify a router type");
        return -1;
    }

    int brute_force_attack_mode = parameter->_brute_force_st->brute_force_attack_mode;
    if (brute_force_attack_mode == BRUTE_FORCE_US_PF)
    {
        if (!(parameter->username))
        {
            ErrorMessage("BRUTE_FORCE_US_PF mode should specify a username");
            return -1;
        }
        else if (!(parameter->password_file_path))
        {
            ErrorMessage("BRUTE_FORCE_US_PF mode should specify a password file path");
            return -1;
        }

        pStrHeader username_list_header;
        GenBruteForceSpecialUsernameList(parameter->username, &username_list_header);
        parameter->_brute_force_st->username_list_header = username_list_header;

        pStrHeader password_list_header;
        GenBruteForcePasswordList(parameter->password_file_path, &password_list_header, INT_MAX);
        parameter->_brute_force_st->password_list_header = password_list_header;
    }
    else if (brute_force_attack_mode == BRUTE_FORCE_UF_PS)
    {
        if (!(parameter->username_file_path))
        {
            ErrorMessage("BRUTE_FORCE_UF_PS mode should specify a username file path");
            return -1;
        }
        else if (!(parameter->password))
        {
            ErrorMessage("BRUTE_FORCE_UF_PS mode should specify a password");
            return -1;
        }
        pStrHeader username_list_header;
        GenBruteForceUsernameList(parameter->username_file_path, &username_list_header, INT_MAX);
        parameter->_brute_force_st->username_list_header = username_list_header;

        pStrHeader password_list_header;
        GenBruteForceSpecialPasswordList(parameter->password, &password_list_header);
        parameter->_brute_force_st->password_list_header = password_list_header;
    }
    else if (brute_force_attack_mode == BRUTE_FORCE_UF_PF)
    {
        if (!(parameter->username_file_path))
        {
            ErrorMessage("BRUTE_FORCE_UF_PF mode should specify a username file path");
            return -1;
        }
        else if (!(parameter->password_file_path))
        {
            ErrorMessage("BRUTE_FORCE_UF_PF mode should specfiy a password file path");
            return -1;
        }
        pStrHeader username_list_header;
        pStrHeader password_list_header;
        GenBruteForceUsernameList(parameter->username_file_path, &username_list_header, INT_MAX);
        GenBruteForcePasswordList(parameter->password_file_path, &password_list_header, INT_MAX);

        parameter->_brute_force_st->username_list_header = username_list_header;
        parameter->_brute_force_st->password_list_header = password_list_header;
    }
    else if (brute_force_attack_mode == BRUTE_FORCE_US_PS)
    {
        if (!(parameter->username))
        {
            ErrorMessage("BRUTE_FORCE_US_PS mode should specify a username");
            return -1;
        }
        else if (!(parameter->password))
        {
            ErrorMessage("BRUTE_FORCE_US_PS mode should specify a password");
            return -1;
        }
        pStrHeader username_list_header;
        pStrHeader password_list_header;
        GenBruteForceSpecialUsernameList(parameter->username, &username_list_header);
        GenBruteForceSpecialPasswordList(parameter->password, &password_list_header);
    }
    else if (brute_force_attack_mode == BRUTE_FORCE_US_PR)
    {
        if (!(parameter->username))
        {
            ErrorMessage("BRUTE_FORCE_US_PR mode should specify a username");
            return -1;
        }
        pStrHeader username_list_header;
        GenBruteForceSpecialUsernameList(parameter->username, &username_list_header);

        pStrHeader password_list_header = (pStrHeader)malloc(sizeof(StrHeader));
        password_list_header->next = NULL;
        password_list_header->length = 0;
    }

    pthread_attr_t attr;
    pthread_t tid[parameter->thread_num];

    int ret;
    for (int i = 0; i < parameter->thread_num; i++)
    {
        //input->serial_num = (i * input->max_thread) + j;
        parameter->seed = i;
        parameter->_brute_force_st->id = i;
        if (pthread_attr_init(&attr))
        {
            ErrorMessage("pthread_attr_init failed");
            return 1;
        }
        //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
        {
            ErrorMessage("StartGuess pthread_attr_setdetachstate failed");
            return 1;
        }
        /* create thread */
        ret = pthread_create(&tid[i], &attr, (void *)_AttackThread, parameter);

        #ifdef DEBUG
        if (ret != 0)
        {
            ErrorMessage("ret: %d", ret);
            ErrorMessage("create pthread failed");
            return -1;
        }
        InfoMessage("tid: %ld", tid[i]);
        #endif

        pthread_attr_destroy(&attr);
    }
    /* join them all */
    //pthread_detach(tid);
    for (int i = 0; i < parameter->thread_num; i++)
    {
        pthread_join(tid[i], NULL);
    }

    #ifdef DEBUG
    InfoMessage("Exit StartAttackProcess");
    #endif

    return 0;
}