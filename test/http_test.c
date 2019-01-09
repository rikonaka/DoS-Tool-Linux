#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAX 80
#define PORT 80

int main(int argc, char const *argv[])
{
    struct sockaddr_in address;
    int sock = 0, valread;
    int enable = 1;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {'\0'};
    char *host = "192.168.1.1";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Error: 1\n");
        return -1;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_addr.s_addr = inet_addr(host);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)))
    {
        return -1;
    }

    /*
    if (inet_pton(AF_INET, "192.168.1.1", &serv_addr.sin_addr) <= 0)
    {
        printf("Error: 2\n");
        return -1;
    }
    */

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("Error: 3\n");
        return -1;
    }

    send(sock, hello, strlen(hello), 0);
    printf("message send\n");
    valread = recv(sock, buffer, 1024, 0);
    printf("%s\n", buffer);
    return 0;
}