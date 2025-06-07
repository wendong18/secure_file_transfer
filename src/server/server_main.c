#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include "../../include/server_socket.h"
#include "../../include/db_init.h"

// 线程参数结构体
typedef struct {
    int client_fd;
} thread_args_t;

// 客户端处理线程函数
void* client_thread(void* arg) {
    thread_args_t* args = (thread_args_t*)arg;
    int client_fd = args->client_fd;
    
    // 释放参数内存
    free(args);
    
    // 分离线程，让系统在线程结束时自动回收资源
    pthread_detach(pthread_self());
    
    // 处理客户端连接
    handle_client(client_fd);
    
    // 线程结束
    return NULL;
}

int main(int argc, char *argv[]) {
    // 忽略SIGPIPE信号，防止客户端断开连接时服务器崩溃
    signal(SIGPIPE, SIG_IGN);
    
    // 初始化数据库
    if (init_database() != 0) {
        fprintf(stderr, "Failed to initialize database\n");
        return 1;
    }
    
    // 初始化服务器套接字
    int server_fd = init_server_socket(8888);
    if (server_fd < 0) {
        fprintf(stderr, "Failed to initialize server socket\n");
        return 1;
    }
    
    printf("Server started on port 8888\n");
    
    // 主循环：接受连接并为每个客户端创建新线程
    while (1) {
        // 接受客户端连接
        int client_fd = accept_client(server_fd);
        if (client_fd < 0) {
            fprintf(stderr, "Failed to accept client connection\n");
            continue;
        }
        
        printf("Client connected, creating new thread\n");
        
        // 创建线程参数
        thread_args_t* args = (thread_args_t*)malloc(sizeof(thread_args_t));
        if (!args) {
            fprintf(stderr, "Failed to allocate memory for thread arguments\n");
            close(client_fd);
            continue;
        }
        args->client_fd = client_fd;
        
        // 创建新线程处理客户端连接
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_thread, args) != 0) {
            fprintf(stderr, "Failed to create thread\n");
            free(args);
            close(client_fd);
            continue;
        }
        
        // 主线程继续接受新的连接
    }
    
    // 关闭服务器套接字（实际上不会执行到这里）
    close(server_fd);
    
    return 0;
}
