#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define ONLY_LETTERS 1
#define ONLY_NUMBERS 2
#define LETTERS_AND_NUMBERS 3
#define LETTERS_AND_PUNCTUATION 4
#define NUMBERS_AND_PUNCTUATION 5
#define ALL_PRINTABLE 6

char *GenRandomPassword(char **result, const unsigned int seed, const int len, const int randomness)
{
    /* 
     * generate the random password
     * 
     * randomness: 
     * 
     */

    char *password = (char *)malloc(len + 1);
    memset(password, 0, len + 1);
    *result = password;
    int random_number;
    int i;

    // srand is here
    srand((int)time(0) + seed);

    i = 0;
    if (randomness == ALL_PRINTABLE)
    {
        while (i < len)
        {
            // [a, b] random interger
            // [33, 126] except space[32]
            // 92 = 126 - 33 - 1
            random_number = 33 + (int)(rand() % 92);
            if (isprint(random_number))
            {
                //snprintf(password, 1, "%s%c", password, random_number);
                password[i] = random_number;
                ++i;
            }
        }
    }
    else if (randomness == ONLY_LETTERS)
    {
        while (i < len)
        {
            // [a, b] random interger
            // [33, 126] except space[32]
            // 92 = 126 - 33 - 1
            random_number = 33 + (int)(rand() % 92);
            if (isprint(random_number))
            {
                if (isalpha(random_number))
                {
                    //snprintf(password, 1, "%s%c", password, random_number);
                    password[i] = random_number;
                    ++i;
                }
            }
        }
    }
    else if (randomness == ONLY_NUMBERS)
    {
        while (i < len)
        {
            // [a, b] random interger
            // [33, 126] except space[32]
            // 92 = 126 - 33 - 1
            random_number = 33 + (int)(rand() % 92);
            if (isprint(random_number))
            {
                if (isdigit(random_number))
                {
                    //snprintf(password, 1, "%s%c", password, random_number);
                    password[i] = random_number;
                    ++i;
                }
            }
        }
    }
    else if (randomness == LETTERS_AND_NUMBERS)
    {
        while (i < len)
        {
            // [a, b] random interger
            // [33, 126] except space[32]
            // 92 = 126 - 33 - 1
            random_number = 33 + (int)(rand() % 92);
            if (isprint(random_number))
            {
                if (isalnum(random_number))
                {
                    //snprintf(password, 1, "%s%c", password, random_number);
                    password[i] = random_number;
                    ++i;
                }
            }
        }
    }
    else if (randomness == LETTERS_AND_PUNCTUATION)
    {
        while (i < len)
        {
            // [a, b] random interger
            // [33, 126] except space[32]
            // 92 = 126 - 33 - 1
            random_number = 33 + (int)(rand() % 92);
            if (isprint(random_number))
            {
                if (!isdigit(random_number))
                {
                    //snprintf(password, 1, "%s%c", password, random_number);
                    password[i] = random_number;
                    ++i;
                }
            }
        }
    }
    else if (randomness == NUMBERS_AND_PUNCTUATION)
    {
        while (i < len)
        {
            // [a, b] random interger
            // [33, 126] except space[32]
            // 92 = 126 - 33 - 1
            random_number = 33 + (int)(rand() % 92);
            if (isprint(random_number))
            {
                if (!isalpha(random_number))
                {
                    //snprintf(password, 1, "%s%c", password, random_number);
                    password[i] = random_number;
                    ++i;
                }
            }
        }
    }
    return password;
}

int main(void)
{
    for (int i = 0; i < 10; ++i)
    {
        char *password = NULL;
        GenRandomPassword(&password, (unsigned int)i, 8, ALL_PRINTABLE);
        printf("passwrod: %s\n", password);
        free(password);
    }

    printf("---------------------------------\n");
    for (int i = 0; i < 10; ++i)
    {
        char *password = NULL;
        GenRandomPassword(&password, (unsigned int)i, 8, ONLY_LETTERS);
        printf("passwrod: %s\n", password);
        free(password);
    }

    printf("---------------------------------\n");
    for (int i = 0; i < 10; ++i)
    {
        char *password = NULL;
        GenRandomPassword(&password, (unsigned int)i, 8, ONLY_NUMBERS);
        printf("passwrod: %s\n", password);
        free(password);
    }

    printf("---------------------------------\n");
    for (int i = 0; i < 10; ++i)
    {
        char *password = NULL;
        GenRandomPassword(&password, (unsigned int)i, 8, LETTERS_AND_NUMBERS);
        printf("passwrod: %s\n", password);
        free(password);
    }

    printf("---------------------------------\n");
    for (int i = 0; i < 10; ++i)
    {
        char *password = NULL;
        GenRandomPassword(&password, (unsigned int)i, 8, LETTERS_AND_PUNCTUATION);
        printf("passwrod: %s\n", password);
        free(password);
    }

    printf("---------------------------------\n");
    for (int i = 0; i < 10; ++i)
    {
        char *password = NULL;
        GenRandomPassword(&password, (unsigned int)i, 8, NUMBERS_AND_PUNCTUATION);
        printf("passwrod: %s\n", password);
        free(password);
    }

    return 0;
}