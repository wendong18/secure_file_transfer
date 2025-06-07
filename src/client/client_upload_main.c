#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../../include/client_socket.h"

int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <username> <password> <local_path> <remote_name>\n", argv[0]);
        return 1;
    }
    const char* username   = argv[1];
    const char* password   = argv[2];
    const char* local_path = argv[3];
    const char* remote     = argv[4];

    // 固定连接到本地 127.0.0.1:8888
    int sfd = connect_to_server("127.0.0.1", 8888);
    if (sfd < 0) {
        perror("connect");
        return 1;
    }

    // 先登录
    if (!login(sfd, username, password)) {
        fprintf(stderr, "Login failed\n");
        close(sfd);
        return 1;
    }

    // 上传
    if (upload_file(sfd, local_path, remote) != 0) {
        fprintf(stderr, "Upload failed\n");
        close(sfd);
        return 1;
    }
    printf("Upload succeeded\n");
    close(sfd);
    return 0;
}

