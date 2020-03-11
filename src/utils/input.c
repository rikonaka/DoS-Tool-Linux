#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../main.h"

extern int ShowMessage(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int InfoMessage(const char *fmt, ...);
extern int DebugMessage(const char *fmtsring, ...);
extern int ErrorMessage(const char *fmt, ...);

extern void DisplayUsage(void);

pInput ProcessInput(const int argc, char *argv[], pInput input)
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
            ErrorMessage("Illegal input");
            return (pInput)NULL;
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
                    ErrorMessage("Can not found value of --set-watch-length parameter");
                    return (pInput)NULL;
                }
            }
            else if (strstr(ptmp2, "ip-repeat-time"))
            {
                if (argv[++i])
                {
                    input->each_ip_repeat = atoi(argv[i]);
                }
                else
                {
                    ErrorMessage("Can not found value of --ip-repeat-time parameter");
                    return (pInput)NULL;
                }
            }
            else if (strstr(ptmp2, "test-guess"))
            {
                input->test_type = TEST_TYPE_GUESS;
            }
            else if (strstr(ptmp2, "test-syn"))
            {
                input->test_type = TEST_TYPE_SYN_FLOOD;
            }
            else if (strstr(ptmp2, "test-udp"))
            {
                input->test_type = TEST_TYPE_UDP_FLOOD;
            }
            else if (strstr(ptmp2, "test-ack-ip-list"))
            {
                input->test_type = TEST_TYPE_ACK_IP_LIST;
            }
            else if (strstr(ptmp2, "test-ack"))
            {
                input->test_type = TEST_TYPE_ACK_REFLECT;
            }
            else if (strstr(ptmp2, "test-dns"))
            {
                input->test_type = TEST_TYPE_DNS_REFLECT;
            }
            else
            {
                ErrorMessage("Illegal input");
                return (pInput)NULL;
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
                        input->attack_mode = GUESS;
                        break;

                    case '1':
                        input->attack_mode = SYN_FLOOD_ATTACK;
                        break;

                    case '2':
                        input->attack_mode = UDP_FLOOD_ATTACK;
                        break;

                    case '3':
                        input->attack_mode = ACK_REFLECT_ATTACK;
                        break;

                    case '4':
                        input->attack_mode = DNS_REFLECT_ATTACK;
                        break;

                    default:
                        DebugMessage("Value of the -a parameter is not allowed, use default value now");
                        input->attack_mode = ATTACK_MODE_DEFAULT;
                        break;
                    }
                }
                else
                {
                    DebugMessage("Can not found value of -a parameter, use default value now");
                    input->attack_mode = ATTACK_MODE_DEFAULT;
                    // return NULL;
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
                        input->debug_level = INFO;
                        break;

                    case '2':
                        input->debug_level = DEBUG;
                        break;

                    case '3':
                        input->debug_level = VERBOSE;
                        break;

                    default:
                        DebugMessage("Value of -d parameter is not allowed, use default value now");
                        input->debug_level = DEBUG_LEVEL_DEFAULT;
                        break;
                    }
                }
                else
                {
                    DebugMessage("Can not found value of -d parameter, use default value now");
                    input->debug_level = DEBUG_LEVEL_DEFAULT;
                    // return NULL;
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
                    DebugMessage("Can not found value of -u parameter, use the default value now");
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
                    ErrorMessage("Can not found value of -U parameter");
                    return (pInput)NULL;
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
                    ErrorMessage("Can not found value of -P parameter");
                    return (pInput)NULL;
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
                    DebugMessage("Can not found value of -t parameter, use default value now");
                    input->max_thread = THREAD_NUM_DEFAULT;
                    // return NULL;
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
                    DebugMessage("Can not found value of -r parameter, use default value now");
                    input->random_password_length = RANDOM_PASSWORD_LENGTH_DEFAULT;
                    // return NULL;
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
                    ErrorMessage("Can not found value of -i parameter");
                    return (pInput)NULL;
                }
                break;

            case 'R':
                // int
                if (argv[++i])
                {
                    switch (*argv[i])
                    {
                    case '0':
                        input->random_sip_address = DISABLE;
                        break;
                    case '1':
                        input->random_sip_address = ENABLE;
                        break;
                    default:
                        DebugMessage("Value of -R parameter is not allowed, use default value now");
                        input->random_sip_address = ENABLE;
                        break;
                    }
                }
                else
                {
                    DebugMessage("Can not found value of -i parameter, use default value now");
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
                    DebugMessage("Can not found value of -m parameter use default value now");
                    strncpy(input->model_type, (char *)MODEL_TYPE_DEFAULT, MAX_MODEL_TYPE_LENGTH);
                }
                break;

            case 'h':
                DisplayUsage();
                //return 0;
                exit(0);

            default:
                ErrorMessage("Please check you input");
                DisplayUsage();
                return (pInput)NULL;
            }
        }
    }

    return input;
}

int CheckInputCompliance(const pInput input)
{
    /*
     * check the compliance of user input
     * like -U must use with -P .etc
     * 
     * return:
     * 0  - check pass
     * -1 - error
     */

    ShowMessage(VERBOSE, input->debug_level, "Enter CheckInputCompliance");

    if (input->test_type != 0)
    {
        InfoMessage("Test model: %d", input->test_type);
        return input->test_type;
    }

    // in the dos attack mode, can not appear 'http' in the address
    if (input->attack_mode != 0)
    {
        if (strstr(input->address, "http"))
        {
            ErrorMessage("Please check your address, this should not appear http or https");
            return 1;
        }
    }

    // -U must with -P
    if (strlen(input->username_path) > 0)
    {
        if (strlen(input->password_path) == 0)
        {
            ErrorMessage("Place check your -U paratemer, -U must use with -P");
            return 1;
        }
    }

    ShowMessage(VERBOSE, input->debug_level, "Exit CheckInputCompliance");
    return 0;
}

pInput *InitInput(pInput *p)
{
    // make sure the buff is clean
    (*p) = (pInput)malloc(sizeof(Input));
    if (!(*p))
    {
        ErrorMessage("Init input malloc failed");
        return (pInput *)NULL;
    }
    if (!memset((*p)->address, 0, sizeof((*p)->address)))
    {
        ErrorMessage("Init input memset failed");
        return (pInput *)NULL;
    }
    if (!memset((*p)->username, 0, sizeof((*p)->username)))
    {
        ErrorMessage("Init input memset failed");
        return (pInput *)NULL;
    }
    if (!memset((*p)->username_path, 0, sizeof((*p)->username_path)))
    {
        ErrorMessage("Init input memset failed");
        return (pInput *)NULL;
    }
    if (!memset((*p)->password_path, 0, sizeof((*p)->password_path)))
    {
        ErrorMessage("Init input memset failed");
        return (pInput *)NULL;
    }
    if (!memset((*p)->model_type, 0, sizeof((*p)->model_type)))
    {
        ErrorMessage("Init input memset failed");
        return (pInput *)NULL;
    }

    // field default value
    (*p)->attack_mode = ATTACK_MODE_DEFAULT;
    (*p)->max_thread = THREAD_NUM_DEFAULT;
    (*p)->debug_level = DEBUG_LEVEL_DEFAULT;
    (*p)->random_password_length = RANDOM_PASSWORD_LENGTH_DEFAULT;
    (*p)->random_sip_address = RANDOM_SIP_DEFAULT;
    (*p)->watch_length = 0;
    (*p)->each_ip_repeat = EACH_IP_REPEAT_TIME;
    (*p)->test_type = TEST_TYPE_NON;
    if (!strncpy((*p)->username, (char *)USERNAME_DEFAULT, strlen((char *)USERNAME_DEFAULT)))
    {
        ErrorMessage("Init input strncpy failed");
        return (pInput *)NULL;
    }
    if (!strncpy((*p)->model_type, (char *)MODEL_TYPE_DEFAULT, strlen((char *)MODEL_TYPE_DEFAULT)))
    {
        ErrorMessage("Init input strncpy failed");
        return (pInput *)NULL;
    }

    return p;
}