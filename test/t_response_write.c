#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

int BruteForceAttackResponseWrite(const char *response)
{
    FILE *fptr;

    // use appropriate location if you are using MacOS or Linux
    fptr = fopen("./response.log", "a+");
    if(fptr == NULL)
    {
        //ErrorMessage("open the response file failed: %s[%d]", errno, strerror(errno));
        return -1;
    }

    time_t t;
    struct tm *time_st;
    time(&t);
    time_st = localtime(&t);
    fprintf(fptr, "%d-%d-%d %d:%d:%d RESULT:\n%s\n\n", time_st->tm_year + 1900, time_st->tm_mon, time_st->tm_mday, time_st->tm_hour, time_st->tm_min, time_st->tm_sec, response);
    fclose(fptr);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *test_1 = "qwertyuiopqwertyuiopqwertyuiop";
    const char *test_2 = "asdfghjkl1234567890!@#$%^&*()";

    BruteForceAttackResponseWrite(test_1);
    BruteForceAttackResponseWrite(test_2);

    return 0;
}