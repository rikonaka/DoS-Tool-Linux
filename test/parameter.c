#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "../main.h"

static int _IsShortParameter(const char *input)
{
    char *input_strip = (char *)malloc(strlen(input));
    input_strip = StripCopy(input_strip, input);
    if ((input_strip[0] == '-') && (input_strip[1] != '-'))
    {
        free(input_strip);
        return TRUE;
    }

    free(input_strip);
    return FALSE;
}

static int _IsLongParameter(const char *input)
{
    char *input_strip = (char *)malloc(strlen(input));
    input_strip = StripCopy(input_strip, input);
    if ((input_strip[0] == '-') && (input_strip[1] == '-') && (input_strip[3] != '-'))
    {
        free(input_strip);
        return TRUE;
    }

    free(input_strip);
    return FALSE;
}

static int _IsParameter(const char *input)
{
    char *input_strip = (char *)malloc(strlen(input));
    input_strip = StripCopy(input_strip, input);
    if (input_strip[0] == '-')
    {
        /* start with '-' is parameter */
        free(input_strip);
        return TRUE;
    }

    free(input_strip);
    return FALSE;
}


void DesParameterSt(pParameter parameter)
{
    if (parameter)
    {
        if (parameter->target_address)
        {
            free(parameter->target_address);
        }

        if (parameter->username)
        {
            free(parameter->username);
        }

        if (parameter->password)
        {
            free(parameter->password);
        }

        if (parameter->username_file_path)
        {
            free(parameter->username_file_path);
        }

        if (parameter->password_file_path)
        {
            free(parameter->password_file_path);
        }

        if (parameter->router_type)
        {
            free(parameter->router_type);
        }

        if (parameter->_brute_force_st)
        {
            if (parameter->_brute_force_st->username_list_header)
            {
                DesBruteForceStrList(parameter->_brute_force_st->username_list_header);
            }

            if (parameter->_brute_force_st->password_list_header)
            {
                DesBruteForceStrList(parameter->_brute_force_st->password_list_header);
            }
            free(parameter->_brute_force_st);
        }

        free(parameter);
    }
}

static int AttackMode(const int argc, const char *argv[])
{
    /*
     * return thr user's attack mode
     */

    int attack_mode = 0;

    for (int i = 1; i < argc; i++)
    {
        /* here must be able to found dashes */
        if (!_IsParameter(argv[i]))
        {
            /* this is value */
            InvalidParameterErrorMessage(argv[i]);
            return -1;
        }

        if (_IsShortParameter(argv[i]))
        {
            /* the option only have one dash */
            p = strstr(argv[i], "-");
            /* *p is '-', so move one postion after '-' */
            switch (*(++p))
            {
                case 'a':
                    // int
                    if (argv[++i])
                    {
                        if (_IsParameter(argv[i]))
                        {
                            /* next thing is parameter not value */
                            ErrorMessage("can not found value of -a parameter");
                            return -1;
                        }

                        else if (strlen(argv[i]) == 1)
                        {
                            switch (*argv[i])
                            {
                                case '1':
                                    attack_mode = BRUTE_FORCE_ATTACK;
                                    break;

                                case '2':
                                    attack_mode = SYN_FLOOD_ATTACK;
                                    break;

                                case '3':
                                    attack_mode = UDP_FLOOD_ATTACK;
                                    break;

                                case '4':
                                    attack_mode = ACK_REFLECT_ATTACK;
                                    break;

                                case '5':
                                    attack_mode = DNS_REFLECT_ATTACK;
                                    break;

                                default:
                                    InvalidParameterErrorMessage(argv[i]);
                                    return -1;
                            }
                        }
                        else if (strlen(argv[i]) > 1)
                        {
                            /* we have not found the 0, 1, 2, 3, 4 in parameter */
                            /* no int value found in the parameter */
                            if (strcmp(argv[i], "guess_password") == 0)
                            {
                                attack_mode = BRUTE_FORCE_ATTACK;
                            }

                            else if (strcmp(argv[i], "syn_flood") == 0)
                            {
                                attack_mode = SYN_FLOOD_ATTACK;
                            }

                            else if (strcmp(argv[i], "udp_flood") == 0)
                            {
                                attack_mode = UDP_FLOOD_ATTACK;
                            }

                            else if (strcmp(argv[i], "ack_reflect") == 0)
                            {
                                attack_mode = ACK_REFLECT_ATTACK;
                            }

                            else if (strcmp(argv[i], "dns_reflect") == 0)
                            {
                                attack_mode = DNS_REFLECT_ATTACK;
                            }
                            else
                            {
                                InvalidParameterErrorMessage(argv[i]);
                                return -1;
                            }
                        }
                    }
                    else
                    {
                        ErrorMessage("can not found value of -a parameter");
                        return -1;
                    }
                    break;

                default:
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
            }
        }
    }

    return attack_mode;
}

int GenParameterSt(const int argc, const char *argv[], pParameter *parameter)
{
    /*
     * get the user input parameter
     */

    int i;
    char *p;
    char *endptr;

    pParameter local_parameter = (pParameter)malloc(sizeof(Parameter));
    #ifdef DEBUG
    if (!local_parameter)
    {
        MallocErrorMessage();
        return -1;
    }
    #endif

    /* force set the char pointer to 0x0 */
    local_parameter->attack_mode = 0;
    local_parameter->target_port = 0;
    local_parameter->thread_num = 0;
    local_parameter->address_type = 0;
    local_parameter->target_address = NULL;
    pBruteForceSt brute_force_st = NULL;
    local_parameter->_brute_force_st = brute_force_st;
    pSynFloodSt syn_flood_st = NULL;
    local_parameter->_syn_flood_st = syn_flood_st;

    int attack_mode = AttackMode(argc, argv);
    local_parameter->attack_mode = attack_mode;
    if (attack_mode == BRUTE_FORCE_ATTACK)
    {
        brute_force_st = (pBruteForceSt)malloc(sizeof(BruteForceSt));
        brute_force_st->username = NULL;
        brute_force_st->password = NULL;
        brute_force_st->username_file_path = NULL;
        brute_force_st->password_file_path = NULL;
        brute_force_st->router_type = NULL;
        brute_force_st->username_encrypt_type = 0;
        brute_force_st->password_encrypt_type = 0;
    }
    else if (attack_mode == SYN_FLOOD_ATTACK)
    {
        syn_flood_st = (pSynFloodSt)malloc(sizeof(SynFloodSt));
        syn_flood_st->random_saddr= DISABLE;
        syn_flood_st->ip_repeat_time = 0;
    }
    
    *parameter = local_parameter;

    for (i = 1; i < argc; i++)
    {
        /* here must be able to found dashes */
        if (!_IsParameter(argv[i]))
        {
            /* this is value */
            InvalidParameterErrorMessage(argv[i]);
            return -1;
        }

        if (_IsShortParameter(argv[i]))
        {
            /* the option only have one dash */
            p = strstr(argv[i], "-");
            /* *p is '-', so move one postion after '-' */
            switch (*(++p))
            {
                case 'a':
                    // int
                    /* same as AttackMode() */
                    break;

                case 'u':
                    // char
                    local_parameter->target_address = (char *)malloc(MAX_URL_LENGTH);
                    #ifdef DEBUG
                    if (!(local_parameter->target_address))
                    {
                        MallocErrorMessage();
                        return -1;
                    }
                    #endif
                    if (!(argv[++i]) || (_IsParameter(argv[i])))
                    {
                        ErrorMessage("can not found value of -u parameter");
                        return -1;
                    }
                    else
                    {
                        strcpy(local_parameter->target_address, argv[i]);
                        //StripCpy(local_parameter->target_address, argv[i]);
                    }
                    break;

                case 'p':
                    // int
                    if (!(argv[++i]) || (_IsParameter(argv[i])))
                    {
                        ErrorMessage("can not found value of -p parameter");
                        return -1;
                    }
                    else
                    {
                        errno = 0;
                        local_parameter->thread_num = strtol(argv[i], &endptr, 10);
                        //p_parameter->thread_num = atoi(argv[i]);
                        if (errno == ERANGE)
                        {
                            ErrorMessage("the value of -p parameter is illegal");
                            return -1;
                        }
                        else if (endptr == argv[i])
                        {
                            ErrorMessage("can not found vaild value of --thread parameter");
                            return -1;
                        }
                    }

                default:
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
            }
        }
        else if (_IsLongParameter(argv[i]))
        {
            p = strstr(argv[i], "--");
            if (strcmp(p, "username-encrypt"))
            {
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                if (argv[++i])
                {
                    if (_IsParameter(argv[i]))
                    {
                        /* next thing is parameter not value */
                        ErrorMessage("can not found value of --username-encrypt parameter");
                        return -1;
                    }

                    else if (strlen(argv[i]) == 1)
                    {
                        switch (*argv[i])
                        {
                            case '0':
                                brute_force_st->username_encrypt_type = NO_ENCRYPT;
                                break;

                            case '1':
                                brute_force_st->username_encrypt_type = BASE64_ENCRYPT;
                                break;

                            default:
                                InvalidParameterErrorMessage(argv[i]);
                                return -1;
                        }
                    }
                    else if (strlen(argv[i]) > 1)
                    {
                        /* we have not found the 0, 1, 2, 3, 4 in parameter */
                        /* no int value found in the parameter */
                        if (strcmp(argv[i], "no_encrypt") == 0)
                        {
                            brute_force_st->username_encrypt_type = NO_ENCRYPT;
                        }
                        else if (strcmp(argv[i], "base64_encrypt") == 0)
                        {
                            brute_force_st->username_encrypt_type= BASE64_ENCRYPT;
                        }
                        else
                        {
                            InvalidParameterErrorMessage(argv[i]);
                            return -1;
                        }
                    }
                }
                else
                {
                    ErrorMessage("can not found value of --username-encrypt parameter");
                    return -1;
                }
            }
            else if (strcmp(p, "password-encrypt"))
            {
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                if (argv[++i])
                {
                    if (_IsParameter(argv[i]))
                    {
                        /* next thing is parameter not value */
                        ErrorMessage("can not found value of --password-encrypt parameter");
                        return -1;
                    }

                    else if (strlen(argv[i]) == 1)
                    {
                        switch (*argv[i])
                        {
                            case '0':
                                brute_force_st->password_encrypt_type= NO_ENCRYPT;
                                break;

                            case '1':
                                brute_force_st->password_encrypt_type= BASE64_ENCRYPT;
                                break;

                            default:
                                InvalidParameterErrorMessage(argv[i]);
                                return -1;
                        }
                    }
                    else if (strlen(argv[i]) > 1)
                    {
                        /* we have not found the 0, 1, 2, 3, 4 in parameter */
                        /* no int value found in the parameter */
                        if (strcmp(argv[i], "no_encrypt") == 0)
                        {
                            brute_force_st->password_encrypt_type = NO_ENCRYPT;
                        }
                        else if (strcmp(argv[i], "base64_encrypt") == 0)
                        {
                            brute_force_st->password_encrypt_type= BASE64_ENCRYPT;
                        }
                        else
                        {
                            InvalidParameterErrorMessage(argv[i]);
                            return -1;
                        }
                    }
                }
                else
                {
                    ErrorMessage("can not found value of --password-encrypt parameter");
                    return -1;
                }
            }
            else if (strcmp(p, "username"))
            {
                // char
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                brute_force_st->username = (char *)malloc(MAX_USERNAME_LENGTH);
                #ifdef DEBUG
                if (!(brute_force_st->username))
                {
                    MallocErrorMessage();
                    return -1;
                }
                #endif
                if ((!argv[++i]) || (_IsParameter(argv[i])))
                {
                    /* the next value should not have - in the start postion*/
                    ErrorMessage("can not found value of --username parameter");
                    return -1;
                }
                else
                {
                    strcpy(brute_force_st->username, argv[i]);
                }
            }
            else if (strcmp(p, "username-file")) 
            {
                // char
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                brute_force_st->username_file_path = (char *)malloc(MAX_USERNAME_FILE_PATH_LENGTH);

                #ifdef DEBUG
                if (!(brute_force_st->username_file_path))
                {
                    MallocErrorMessage();
                    return -1;
                }
                #endif

                if (!(argv[++i]) || (_IsParameter(argv[i])))
                {
                    ErrorMessage("can not found value of --username-file parameter");
                    return -1;
                }
                else if (strlen(argv[i]) != 0)
                {
                    strcpy(brute_force_st->username_file_path, argv[i]);
                }
            }

            else if (strcmp(p, "password-file"))
            {
                // char
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                brute_force_st->password_file_path = (char *)malloc(MAX_PASSWORD_FILE_PATH_LENGTH);

                #ifdef DEBUG
                if (!(brute_force_st->password_file_path))
                {
                    MallocErrorMessage();
                    return -1;
                }
                #endif

                if (!(argv[++i]) || (_IsParameter(argv[i])))
                {
                    ErrorMessage("can not found value of --password-file parameter");
                    return -1;
                }
                else
                {
                    strcpy(brute_force_st->password_file_path, argv[i]);
                }
            }
            else if (strcmp(p, "thread"))
            {
                // int
                if (!(argv[++i]) || (_IsParameter(argv[i])))
                {
                    ErrorMessage("can not found value of --thread parameter");
                    return -1;
                }
                else
                {
                    errno = 0;
                    local_parameter->thread_num = strtol(argv[i], &endptr, 10);
                    //p_parameter->thread_num = atoi(argv[i]);
                    if (errno == ERANGE)
                    {
                        ErrorMessage("the value of --tread parameter is illegal");
                        return -1;
                    }
                    else if (endptr == argv[i])
                    {
                        ErrorMessage("can not found vaild value of --thread parameter");
                        return -1;
                    }
                }
            }
            else if (strcmp(p, "password-random-length"))
            {
                // int
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                if (!(argv[++i]) || (_IsParameter(argv[i])))
                {
                    ErrorMessage("can not found value of --password-random-length parameter");
                    return -1;
                }
                else
                {
                    errno = 0;
                    brute_force_st->random_password_length = strtol(argv[i], &endptr, 10);
                    //p_parameter->passwd_len = atoi(argv[i]);
                    if (errno == ERANGE)
                    {
                        ErrorMessage("the value of --random-password-length parameter is illegal");
                        return -1;
                    }
                    else if (endptr == argv[i])
                    {
                        ErrorMessage("can not found vaild value of --random-password-length parameter");
                        return -1;
                    }
                }
            }
            else if (strcmp(p, "password-randomness") == 0)
            {
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                if (!(argv[++i]) || (_IsParameter(argv[i])))
                {
                    ErrorMessage("can not found value of --password-randomness parameter");
                    return -1;
                }
                else
                {
                    errno = 0;
                    brute_force_st->password_randomness = strtol(argv[i], &endptr, 10);
                    //p_parameter->passwd_len = atoi(argv[i]);
                    if (errno == ERANGE)
                    {
                        ErrorMessage("the value of --password-randomness parameter is illegal");
                        return -1;
                    }
                    else if (endptr == argv[i])
                    {
                        ErrorMessage("can not found vaild value of --password-randomness parameter");
                        return -1;
                    }
                }
            }
            else if (strcmp(p, "random-saddr"))
            {
                // int
                if (!syn_flood_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                syn_flood_st->random_saddr = ENABLE;
            }
            else if (strcmp(p, "ip-repeat-time") == 0)
            {
                // int
                if (!(argv[++i]) || (_IsParameter(argv[i])))
                {
                    ErrorMessage("can not found value of --each-ip-repeat-time parameter");
                    return -1;
                }
                else
                {
                    errno = 0;
                    local_parameter->ip_repeat_time = strtol(argv[i], &endptr, 10);
                    //p_parameter->ip_repeat_time = atoi(argv[i]);
                    if (errno == ERANGE)
                    {
                        ErrorMessage("the value of --each-ip-repeat-time parameter is illegal");
                        return -1;
                    }
                    else if (endptr == argv[i])
                    {
                        ErrorMessage("can not found vaild value of --each-ip-repeat-time parameter");
                        return -1;
                    }
                }
            }
            else if (strcmp(p, "router") == 0)
            {
                // char
                if (!brute_force_st)
                {
                    InvalidParameterErrorMessage(argv[i]);
                    return -1;
                }
                brute_force_st->router_type = (char *)malloc(MAX_ROUTER_TYPE_LENGTH);
                #ifdef DEBUG
                if (!(brute_force_st->router_type))
                {
                    MallocErrorMessage();
                    return -1;
                }
                #endif
                if (!(argv[++i]) || (_IsParameter(argv[i])))
                {
                    ErrorMessage("can not found value of --each-ip-repeat-time parameter");
                    return -1;
                }
                else
                {
                    strncpy(brute_force_st->router_type, argv[i], MAX_ROUTER_TYPE_LENGTH);
                }
            }
            else if (strcmp(p, "help"))
            {
                // help
                usage();
                exit(0);
            }
            else
            {
                InvalidParameterErrorMessage(argv[i]);
                return -1;
            }
        }
    }

    return 0;
}
