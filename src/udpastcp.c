#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "common.h"
#include "server.h"
#include "client.h"

int free_mem_on_exit = 0;
void *libpcap = NULL;

void usage() {
    puts("usage: udpintcp [OPTION]...\n"
            "Make UDP look like TCP.\n"
            "\n"
            "  -m MODE                          Client/server mode.\n"
            "  -h LISTEN_HOST -p LISTEN_PORT    Listen on the specified host/port. Port is required.\n"
            "  -H REMOTE_HOST -P REMOTE_PORT    Connect to the specified host/port. Always required.\n"
            "  -d DEVICE                        Use libpcap and listen on the specified interface.\n");
}

int main(int argc, char *argv[]) {
    char ch;
    struct common_data common_data = {
        .listen_host = "::"
    };
    const char *mode = NULL;
    while ((ch = getopt(argc, argv, "m:h:p:H:P:d:")) != -1) {
        switch (ch) {
        case 'm':
            mode = optarg;
            break;
        case 'h':
            common_data.listen_host = optarg;
            break;
        case 'p':
            common_data.listen_port = optarg;
            break;
        case 'H':
            common_data.remote_host = optarg;
            break;
        case 'P':
            common_data.remote_port = optarg;
            break;
        case 'd':
            common_data.device = optarg;
            break;
        case '?':
            usage();
            break;
        default:
            abort();
        }
        if (optind > argc) {
            fputs("extra arguments on command line\n", stderr);
            exit(EXIT_FAILURE);
        }
    }
    if (!mode) {
        fputs("missing required argument: mode", stderr);
        exit(EXIT_FAILURE);
    }
    if (!common_data.listen_port) {
        fputs("missing required argument: listen port", stderr);
        exit(EXIT_FAILURE);
    }
    if (!common_data.remote_host) {
        fputs("missing required argument: remote host", stderr);
        exit(EXIT_FAILURE);
    }
    if (!common_data.remote_port) {
        fputs("missing required argument: remote port", stderr);
        exit(EXIT_FAILURE);
    }

    srandom((unsigned int)time(NULL));

    if (getenv("UDPASTCP_RELEASE_MEMORY")) {
        DBG("UDPASTCP_RELEASE_MEMORY is set, will free all memory on exit.");
        free_mem_on_exit = 1;
    }

    int (*startf)(struct common_data *);

    if (!strcmp(mode, "client")) {
        startf = start_client;
    } else if (!strcmp(mode, "server")) {
        startf = start_server;
    } else {
        fputs("invalid mode\n", stderr);
        return 1;
    }

    DBG("starting %s listening on [%s]:%s connecting to [%s]:%s", mode, common_data.listen_host, common_data.listen_port, common_data.remote_host, common_data.remote_port);
    return startf(&common_data);
}
