#include <string.h>
#include <stdio.h>


int main(void)
{
    int n = 16;
    char data[100];
    for (int i = 0; i < n; i++)
    {
        memcpy(data + (i * 4), "love", 4);
    }
    return 0;
}