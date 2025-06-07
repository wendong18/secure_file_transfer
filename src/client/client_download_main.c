#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../../include/client_socket.h"

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <username> <password> <remote_name> <local_path>\n", argv[0]);
        return 1;
    }
    const char* username   = argv[1];
    const char* password   = argv[2];
    const char* remote     = argv[3];
    const char* local_path = argv[4];

    int sfd = connect_to_server("127.0.0.1", 8888);
    if (sfd < 0) {
        perror("connect");
        return 1;
    }

    if (!login(sfd, username, password)) {
        fprintf(stderr, "Login failed\n");
        close(sfd);
        return 1;
    }

    if (download_file(sfd, remote, local_path) != 0) {
        fprintf(stderr, "Download failed\n");
        close(sfd);
        return 1;
    }
    printf("Download succeeded\n");
    close(sfd);
    return 0;
}

