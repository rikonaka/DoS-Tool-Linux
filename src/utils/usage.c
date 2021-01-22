#include <stdio.h>
#include <stdlib.h>

void usage(void)
{
    /*
     * show the useage info
     */

    char *usage = "\n"
                  "Usage: dos-tool-linux -u [address] -p [port] -a [mode]\n"
                  "\n"
                  "Example:\n"
                  "./dos-tool-linux -u 192.168.1.1 -p 80 -a 1 (syn flood attack target's 80 port)\n"
                  "./dos-tool-linux -u 192.168.1.1 -p 80 -a syn_flood (syn flood attack target's 80 port)\n"
                  "\n"
                  "-u (or use --url) [address]           specify intent URL or IP address\n"
                  "-p (or use --port) [port]             specify port"
                  "-a (or use --attack-mode) [mode]      specify attack mode\n"
                  "                                          1 syn flood attack\n"
                  "                                          2 udp flood attack\n"
                  "                                          3 ack flood attack\n"
                  "                                          4 syn + ack joint attack\n"
                  "                                          5 ack reflect attack\n"
                  "                                          6 dns reflect attack\n"
                  "                                          7 http(s) flood attack\n"
                  "-t (or use --thread) [number]         specify the attack thread number (default 4)\n"
                  "--help                                show this help message again\n"
                  "--random-src                          enable the random source IP address in syn flood attack\n"
                  "                                      (default enabled)\n"
                  "--repeat-times [time]                 specify the number of repetitions of the random source IP address in syn\n"
                  "                                      (or ack or syn ack joint) flood attack (default 128)\n"
                  "--src-addr [ip]                       specify the syn flood source IP address which will see by victim\n"
                  "                                      (default 192.168.1.2)\n"
                  "--src-port [port]                     specify the syn flood source port which will see by victim\n"
                  "                                      (default 9999)\n"
                  "--udp-dynamic-packet                  enable the udp flood packet dynamic packet size\n"
                  "--udp-dynamic-dst-port                enable the udp flood attack to target's all port not just one\n"
                  "--http-request [request file path]    specify the http send request content path\n"
                  "--https-request [request file path]   specify the https send request content path\n"
                  "\n"
                  "";

    printf("%s", usage);
    exit(0);
}