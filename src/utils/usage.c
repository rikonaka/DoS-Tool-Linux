#include <stdio.h>

void ShowUsage(void)
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
                  "-u [or --url]                         specify intent URL or IP address\n"
                  "-p [or --port]                        specify port"
                  "-a [or --attack-mode]                 specify attack mode\n"
                  "                                          1 (or use guess_password) brute force attack\n"
                  "                                          2 (or use syn_flood) syn flood attack\n"
                  "                                          3 (or use udp_flood) udp flood attack\n"
                  "                                          4 (or use ack_reflect) ack reflect attack\n"
                  "                                          5 (or use dns_reflect) dns reflect attack\n"
                  "--random-source-address               specify the program enable random source address in dos attack (brute force attack not support)\n"
                  "--thread [number]                     specify the attack thread number (default 4)\n"
                  "--ip-repeat-time [time]               specify times which random source ip change to next address\n"
                  "--help                                show this help message again\n"
                  "\n"
                  "";

    printf("%s", usage);
    exit(0);
}