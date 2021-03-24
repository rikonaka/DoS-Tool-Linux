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
                  "-u (or --url) [address]              specify intent URL or IP address\n"
                  "-p (or --port) [port]                specify port"
                  "-a (or --am) [mode]                  specify attack mode\n"
                  "                                          1 syn flood attack\n"
                  "                                          2 udp flood attack\n"
                  "                                          3 ack flood attack\n"
                  "                                          4 syn + ack joint attack\n"
                  "                                          5 ack reflect attack\n"
                  "                                          6 dns reflect attack\n"
                  "                                          7 http(s) flood attack\n"
                  "-n (or --pn) [number]                 specify the how many attack packets will send\n"
                  "                                          (default __INT32_MAX__: 2147483647, max __UINT32_MAX__: 4294967295)\n"
                  "                                          (set the value 0 to infinite loop)\n"
                  "-t (or --thread) [number]             specify the attack thread number (default 4)\n"
                  "--help                                show this help message again\n"
                  "--rdsrc                               enable the random source IP in\n"
                  "                                          syn flood attack\n"
                  "                                          ack flood attack\n"
                  "                                          (default enabled)\n"
                  "--rt [time]                           specify the number of repetitions of the random source IP address in syn\n"
                  "                                      (or ack or syn ack joint) flood attack\n"
                  "                                          (default 128)\n"
                  "--saddr [ip]                          specify a fake syn flood source IP address which will see by victim\n"
                  "                                          (default 192.168.1.2)\n"
                  "--sport [port]                        specify a fake syn flood source port which will see by victim\n"
                  "                                          (default 9999)\n"
                  "--udps                                enable the udp flood packet dynamic packet size\n"
                  "--uddp                                enable the udp flood attack to target's all(random) port not just one\n"
                  "--https                               specify the http flood attack target is a https websites\n"
                  "                                          (default http)"
                  "--request [request file]              specify the http(s) request content file path\n"
                  "\n"
                  "";

    printf("%s", usage);
    exit(0);
}