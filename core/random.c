#include <stdio.h>

#include "random.h"

int GetRandomString(char *rebuf, const struct RAND_INPUT *input)
{
    /* NOTE:
     * rebuf        Which to store the data, definition in exploit.c
     * Flag         If flag=0, output the username random string, else output password random string
     * NumLoop      [0, 1024] loop to generate the randome number in one seconds
     * DebugMode    Show more infomation
     */

    int MAX;
    char *strtmp = NULL;

    struct RAND_INPUT *ptmp = (struct RAND_INPUT *)input;
    struct GINPUT *sinput = (struct GINPUT *)malloc(sizeof(struct GINPUT));

    if (ptmp->RandFlag == 0)
    {
        MAX = (int)MY_RAND_MAX_USERNAME_LENGTH;
        strtmp = (char *)calloc((MAX + 1), sizeof(char));
        sinput->Seed = (float)ptmp->NumLoop + ptmp->Seed;
        sinput->Max = (float)MAX;
        strtmp = grand_passwd(sinput);
    }
    else if (ptmp->RandFlag == 1)
    {
        MAX = (int)MY_RAND_MAX_PASSWORD_LENGTH;
        strtmp = (char *)calloc((MAX + 1), sizeof(char));
        sinput->Seed = (float)ptmp->NumLoop + ptmp->Seed;
        sinput->Max = (float)MAX;
        strtmp = grand_passwd(sinput);
    }
    //free(sinput);
    strcpy(rebuf, strtmp);
}