#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "common.h"
#include "server.h"
#include "client.h"

int free_mem_on_exit = 0;

int main(int argc, char *argv[]) {
    if (argc < 6) {
        puts("usage: udpintcp client|server LISTEN_HOST LISTEN_PORT REMOTE_HOST REMOTE_PORT");
        return !(argc == 2 && !strcmp(argv[1], "--help"));
    }

    srandom((unsigned int)time(NULL));

    if (getenv("UDPASTCP_RELEASE_MEMORY")) {
        DBG("UDPASTCP_RELEASE_MEMORY is set, will free all memory on exit.");
        free_mem_on_exit = 1;
    }

    if (!strcmp(argv[1], "client")) {
        DBG("starting client listening on [%s]:%s connecting to [%s]:%s", argv[2], argv[3], argv[4], argv[5]);
        return start_client(argv[2], argv[3], argv[4], argv[5]) == 0;
    } else if (!strcmp(argv[1], "server")) {
        DBG("starting server listening on [%s]:%s connecting to [%s]:%s", argv[2], argv[3], argv[4], argv[5]);
        return start_server(argv[2], argv[3], argv[4], argv[5]) == 0;
    } else {
        fputs("invalid mode\n", stderr);
        return 1;
    }
}
