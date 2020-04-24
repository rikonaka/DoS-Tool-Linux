#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LEN 20

int main(int argc, char *argv[])
{
    FILE *fp = fopen("./test.txt", "r");
    if (!fp)
    {
        printf("Error");
        return -1;
    }


    size_t str_len = LEN;
    char *str = (char *)malloc(str_len* sizeof(char));
    char ch = fgetc(fp);
    while (ch && ch != '\n' && ch != '\r' && !feof(fp))
    {
        if (str_len <= strlen(str))
        {
            str_len = str_len + LEN;
            str = (char *)realloc(str, str_len);
        }
        sprintf(str, "%s%c", str, ch);
        ch = fgetc(fp);
    }
    fclose(fp);
    printf(str);
    printf("\n");
    return 0;
}