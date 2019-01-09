#include <stdio.h>
#include <string.h>


int SplitURL(const char *url, char **host, char **suffix, int *port)
{
    /*
     * This function will split the url
     * Example with url = 'http://192.168.20.1:8080/index.html'
     * After parse:
     *    host = "192.168.20.1"
     *    suffix = "index.html"
     *    port = 8080
     * 
     * input:
     *     url
     * output:
     *     host
     *     suffix
     *     port
     */

    char tr1[MAX_URL_LENGTH];
    strncpy(tr1, url, MAX_URL_LENGTH);
    char *ptr1 = tr1;
    char *ptr2;
    char *ptr3;

    ptr1 = strchr(ptr1, '/');
    if (!ptr1 || *(++ptr1) != '/')
    {
        /*
         * check here
         *       |
         * http://192.168.1.1/index.html
         * 
         */

        DisplayError("Please check your URL address");
        return -1;
    }
    /* cut the 'http:\\' */
    *ptr1 = '\0';
    ++ptr1;

    ptr2 = strchr(ptr1, '/');

    if (!ptr2)
    {
        DisplayError("Please check your URL address");
        return -1;
    }
    else
    {
        // Execute here mean program found the '/'
        // Now ptr1 and ptr2 status is here:
        //      ptr1              ptr2
        //       |                 |
        // http://192.168.20.1:8080/index.html
        // len is same as the strlen("192.168.20.1")
        *ptr2 = '\0';

        // Only copy the IP(192.168.20.1:8080) address to host
        // There sentence is judge the (index.html) is existed or not
        if (*(++ptr2))
        {
            // Copy the 'index.html' to file except the frist character '\'
            // Fill in the last blank with '\0'
            *suffix = ptr2;
            //strncpy(*suffix, ptr2, strlen(ptr2));
        }
    }

    // Now split host and ip
    ptr3 = strchr(ptr1, ':');
    if (!ptr3)
    {
        DisplayWarning("No port found, use default value <%d> now", PORT_DEFAULT);
        *port = PORT_DEFAULT;
    }
    else
    {
        /* Now ptr3 status:
         *            ptr3
         *             |
         * 192.168.20.1:8080
         */
        *ptr3 = '\0';
        ++ptr3;
        // Make the port point to (int)8080
        *port = atoi(ptr3);
    }
    *host = ptr1;
    //strncpy(*host, ptr1, strlen(ptr1));
    return 0;
}

int main(void)
{
    int src = 1234;
    src <<= 1;
    src >>= 1;
    return 0;
}