#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LEN 20

/*
int main(int argc, char *argv[])
{
    FILE *fp = fopen("./test.txt", "r");
    if (!fp)
    {
        printf("Error");
        return -1;
    }


    size_t str_len = LEN;
    char *str = (char *)malloc(str_len);
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
*/

static char *_read_file(const char *path)
{
    int cursor = 0;
    char ch;
    // char ch_cr = '\r';
    // char ch_lf = '\n';
    // ASCII
    unsigned int ch_lf = 10;
    unsigned int ch_cr = 13;

    FILE *fp = fopen(path, "r");

    fseek(fp, 0L, SEEK_END);
    long sz = ftell(fp); // file size
    rewind(fp);

    char *buff = (char *)calloc(sz * 2, sizeof(char));
    while (1)
    {
        ch = fgetc(fp);
        if (ch == EOF)
            break;
        else if ((unsigned int)ch != 10 && (unsigned int)ch != 13)
            buff[cursor++] = ch;
        else
        {
            buff[cursor++] = ch_cr;
            buff[cursor++] = ch_lf;
        }
    }
    fclose(fp);
    buff[cursor++] = ch_cr;
    buff[cursor++] = ch_lf;
    buff[cursor++] = ch_cr;
    buff[cursor++] = ch_lf;

    return buff;
}

int main(void)
{
    char *path = "./test.txt";
    char *config = _read_file(path);

    free(config);
    return 0;
}