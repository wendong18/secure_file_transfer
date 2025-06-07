// src/server/server_socket.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>       // for uint64_t, uint32_t
#include <unistd.h>       // for close()
#include <arpa/inet.h>    // for socket / htonl / htons / ntohl / ntohs
#include <netinet/in.h>
#include <netinet/tcp.h>  // for TCP_NODELAY
#include <sys/socket.h>
#include <time.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/types.h>

#include "../../include/common.h"
#include "../../include/user_auth.h"
#include "../../include/server_socket.h"
#include "../../include/sm4.h"
#include "../../include/sm2.h"
#include "../../include/file_io.h"
#include "../../include/file_manager.h"

// 消息类型定义
// 注：在server_socket.h中已定义，这里不再重复定义
// 使用include/server_socket.h中的定义

// 64-bit network byte order conversions
static inline uint64_t htonll(uint64_t v) {
    return (((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFF))) << 32)
         | htonl((uint32_t)(v >> 32));
}
static inline uint64_t ntohll(uint64_t v) {
    return htonll(v);
}

// 函数声明
void escape_json_string(const char* input, char* output, size_t output_size);

int init_server_socket(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = { .s_addr = INADDR_ANY }
    };
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(sockfd); return -1;
    }
    if (listen(sockfd, 5) < 0) {
        perror("listen"); close(sockfd); return -1;
    }
    printf("[SERVER] Listening on %d\n", port);
    return sockfd;
}

int accept_client(int server_fd) {
    struct sockaddr_in cli;
    socklen_t len = sizeof(cli);
    int client_fd = accept(server_fd, (struct sockaddr*)&cli, &len);
    if (client_fd < 0) {
        perror("accept");
    } else {
        printf("[SERVER] Client %s connected\n", inet_ntoa(cli.sin_addr));
        
        // 设置套接字选项
        int flag = 1;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
            perror("setsockopt TCP_NODELAY");
        }
        
        // 设置发送和接收超时
        struct timeval tv;
        tv.tv_sec = 5;  // 5秒超时
        tv.tv_usec = 0;
        if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_SNDTIMEO");
        }
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt SO_RCVTIMEO");
        }
        
        // 设置缓冲区大小
        int buf_size = 65536;  // 64KB
        if (setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
            perror("setsockopt SO_SNDBUF");
        }
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
            perror("setsockopt SO_RCVBUF");
        }
    }
    return client_fd;
}

// 添加辅助函数以适配新旧函数接口
int get_user_id_by_name(const char* username) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int user_id = -1;
    
    if (!username) return -1;
    
    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    const char* sql = "SELECT user_id FROM users WHERE username = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
        fprintf(stderr, "Found user '%s' with ID: %d\n", username, user_id);
    } else {
        fprintf(stderr, "User '%s' not found in database\n", username);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return user_id;
}

// 添加处理日志请求的函数
int handle_get_logs_request(int client_fd, int user_id) {
    fprintf(stderr, "[SERVER] Handling logs request for user %d\n", user_id);
    
    // 构造响应头
    char header[2] = {MSG_LIST_LOGS_RESP, 1}; // 1表示成功
    
    // 打开数据库
    sqlite3 *db = NULL;
    
    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
        fprintf(stderr, "[SERVER] Failed to open database: %s\n", sqlite3_errmsg(db));
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    fprintf(stderr, "[SERVER] Database opened successfully\n");
    
    // 检查用户是否存在
    char username[64] = {0};
    if (!get_username_by_id(user_id, username, sizeof(username))) {
        fprintf(stderr, "[SERVER] User ID %d not found\n", user_id);
        char resp[2] = { MSG_LIST_LOGS_RESP, 0 }; // 失败
        send(client_fd, resp, 2, 0);
        return -1;
    }
    
    fprintf(stderr, "[SERVER] User verified: %s (ID=%d)\n", username, user_id);
    
    // 检查用户权限
    int admin = is_admin(user_id);
    fprintf(stderr, "[SERVER] User %s (ID=%d) is %sadmin\n", username, user_id, admin ? "" : "not ");
    
    // 使用list_logs函数获取日志数据
    char result[16384] = {0}; // 增大缓冲区以容纳更多日志
    fprintf(stderr, "[SERVER] Calling list_logs for user %d (admin=%d)\n", user_id, admin);
    
    int count = list_logs(user_id, admin, result, sizeof(result));
    
    fprintf(stderr, "[SERVER] list_logs returned %d entries\n", count);
    
    if (count < 0) {
        fprintf(stderr, "[SERVER] Failed to get logs\n");
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 如果结果为空，确保至少返回一个空的JSON数组
    if (result[0] == '\0') {
        strcpy(result, "[]");
        fprintf(stderr, "[SERVER] No logs found, returning empty array\n");
    }
    
    // 发送响应头
    fprintf(stderr, "[SERVER] Sending logs response header [%02x %02x]\n", 
            (unsigned char)header[0], (unsigned char)header[1]);
    
    int header_sent = 0;
    int retry_count = 0;
    const int max_retries = 5;
    
    // 使用循环确保完整发送响应头
    while (header_sent < 2 && retry_count < max_retries) {
        int s = send(client_fd, header + header_sent, 2 - header_sent, 0);
        if (s > 0) {
            header_sent += s;
        } else if (s < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                fprintf(stderr, "[SERVER] Temporary error sending header, retrying: %s\n", strerror(errno));
                retry_count++;
                usleep(100000); // 休眠100毫秒后重试
                continue;
            }
            fprintf(stderr, "[SERVER] Failed to send logs response header: error=%s\n", strerror(errno));
            sqlite3_close(db);
            return -1;
        } else {
            fprintf(stderr, "[SERVER] Connection closed while sending header\n");
            sqlite3_close(db);
            return -1;
        }
    }
    
    if (header_sent != 2) {
        fprintf(stderr, "[SERVER] Failed to send complete logs response header after %d retries\n", max_retries);
        sqlite3_close(db);
        return -1;
    }
    
    // 发送日志数据
    size_t result_len = strlen(result);
    fprintf(stderr, "[SERVER] Sending %zu bytes of logs data: %s\n", result_len, result);
    
    int data_sent = 0;
    retry_count = 0;
    
    // 使用循环确保完整发送日志数据
    while ((size_t)data_sent < result_len && retry_count < max_retries) {
        int s = send(client_fd, result + data_sent, result_len - data_sent, 0);
        if (s > 0) {
            data_sent += s;
            fprintf(stderr, "[SERVER] Sent %d/%zu bytes of logs data\n", data_sent, result_len);
        } else if (s < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                fprintf(stderr, "[SERVER] Temporary error sending data, retrying: %s\n", strerror(errno));
                retry_count++;
                usleep(100000); // 休眠100毫秒后重试
                continue;
            }
            fprintf(stderr, "[SERVER] Failed to send logs data: error=%s\n", strerror(errno));
            sqlite3_close(db);
            return -1;
        } else {
            fprintf(stderr, "[SERVER] Connection closed while sending data\n");
            sqlite3_close(db);
            return -1;
        }
    }
    
    if ((size_t)data_sent != result_len) {
        fprintf(stderr, "[SERVER] Failed to send complete logs data after %d retries: sent %d/%zu bytes\n", 
                max_retries, data_sent, result_len);
        sqlite3_close(db);
        return -1;
    }
    
    fprintf(stderr, "[SERVER] Successfully sent %d log entries (%zu bytes) to user %d\n", 
            count, result_len, user_id);
    
    // 记录此次获取日志的操作
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(client_fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        
        char log_msg[128] = {0};
        snprintf(log_msg, sizeof(log_msg), "Retrieved %d log entries", count);
        
        add_log(user_id, username, "view_logs", log_msg, ip);
        fprintf(stderr, "[SERVER] Logged view_logs operation for user %d (%s)\n", user_id, username);
    }
    
    sqlite3_close(db);
    return 0;
}

// 转义JSON字符串中的特殊字符
void escape_json_string(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size == 0) return;
    
    size_t i = 0, j = 0;
    
    // 确保至少有足够空间放置一个空字符
    output_size--;
    
    while (input[i] && j < output_size) {
        char c = input[i++];
        
        // 转义JSON特殊字符
        switch (c) {
            case '\\': 
                if (j + 1 < output_size) {
                    output[j++] = '\\';
                    output[j++] = '\\';
                }
                break;
            case '"': 
                if (j + 1 < output_size) {
                    output[j++] = '\\';
                    output[j++] = '"';
                }
                break;
            case '\b': 
                if (j + 1 < output_size) {
                    output[j++] = '\\';
                    output[j++] = 'b';
                }
                break;
            case '\f': 
                if (j + 1 < output_size) {
                    output[j++] = '\\';
                    output[j++] = 'f';
                }
                break;
            case '\n': 
                if (j + 1 < output_size) {
                    output[j++] = '\\';
                    output[j++] = 'n';
                }
                break;
            case '\r': 
                if (j + 1 < output_size) {
                    output[j++] = '\\';
                    output[j++] = 'r';
                }
                break;
            case '\t': 
                if (j + 1 < output_size) {
                    output[j++] = '\\';
                    output[j++] = 't';
                }
                break;
            default:
                // 只复制可打印字符和标准ASCII
                if ((c >= 32 && c <= 126) || (unsigned char)c >= 128) {
                    output[j++] = c;
                }
                break;
        }
    }
    
    // 确保字符串以NULL结尾
    output[j] = '\0';
}

void handle_client(int client_fd) {
    char buf[4096];  // 增大缓冲区
    int  n;
    int  uid = -1;  // 登录后保存 user_id

    // 设置套接字为非阻塞模式
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

    // 使用select进行超时处理
    fd_set readfds;
    struct timeval tv;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        tv.tv_sec = 30;  // 30秒超时
        tv.tv_usec = 0;

        int activity = select(client_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (activity < 0) {
            if (errno == EINTR) continue;  // 被信号中断，重试
            perror("select");
            break;
        }
        
        if (activity == 0) {
            printf("[SERVER] Client connection timed out\n");
            break;  // 超时，关闭连接
        }
        
        if (FD_ISSET(client_fd, &readfds)) {
            n = recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;  // 暂时没有数据可读
                    }
                    perror("recv");
                }
                break;  // 连接关闭或出错
            }
            
            unsigned char cmd = (unsigned char)buf[0];
            printf("[SERVER] Received command: %02x, length: %d\n", cmd, n);
            
            // 忽略ping命令
            if (cmd == 0xFF) {
                printf("[SERVER] Received ping from client\n");
                continue;
            }

            // 处理注册请求
            if (cmd == MSG_USER_MANAGE && buf[1] == 1) {
                char *username = &buf[2];
                char *password = NULL;
                
                // 安全检查：确保username字符串有效
                if (n <= 2 || strlen(username) >= sizeof(buf) - 2) {
                    printf("[SERVER] Invalid register request: username too long or missing\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 安全地找到密码字段
                size_t username_len = strlen(username);
                if ((size_t)n > 2 + username_len + 1) { // 确保有足够的数据包含密码
                    password = username + username_len + 1;
                    
                    // 确保密码字符串有效
                    if (strlen(password) >= sizeof(buf) - 1 - username_len - 1) {
                        printf("[SERVER] Invalid register request: password too long\n");
                        char resp[2] = { MSG_RESULT, 0 }; // 失败
                        send(client_fd, resp, 2, 0);
                        continue;
                    }
                } else {
                    printf("[SERVER] Invalid register request: password missing\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                printf("[SERVER] Register attempt: %s\n", username);
                
                // 验证用户名和密码格式
                if (strlen(username) < 3 || strlen(password) < 6) {
                    printf("[SERVER] Invalid username or password length\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 检查用户名是否已存在
                if (check_username_exists(username) > 0) {
                    printf("[SERVER] Username %s already exists\n", username);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 注册用户
                int result = register_user(username, password);
                printf("[SERVER] Register result for %s: %d\n", username, result);
                
                char resp[2] = { MSG_RESULT, (result == 0) ? 1 : 0 };
                
                // 确保响应被完整发送
                int sent = 0;
                while (sent < 2) {
                    int s = send(client_fd, resp + sent, 2 - sent, 0);
                    if (s <= 0) {
                        if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                            continue;  // 暂时无法发送，重试
                        }
                        perror("send register response");
                        break;
                    }
                    sent += s;
                }
                
                // 记录注册日志
                if (result == 0) {
                    // 获取客户端IP
                    struct sockaddr_in addr; socklen_t len=sizeof(addr);
                    getpeername(client_fd, (struct sockaddr*)&addr, &len);
                    char ip[32]={0}; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                    int new_uid = get_user_id(username);
                    add_log(new_uid, username, "register", "", ip);
                }
            }
            else if (cmd == MSG_LOGIN) {
                char *username = &buf[1];
                char *password = username + strlen(username) + 1;
                printf("[SERVER] Login attempt: %s\n", username);
                int ok = login_user(username, password);
                if (ok) {
                    uid = get_user_id(username);
                    printf("[SERVER] User '%s' logged in as UID=%d\n", username, uid);
                    // 获取客户端IP
                    struct sockaddr_in addr; socklen_t len=sizeof(addr);
                    getpeername(client_fd, (struct sockaddr*)&addr, &len);
                    char ip[32]={0}; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                    add_log(uid, username, "login", "", ip);
                }
                
                // 修改响应，添加管理员标志
                // 如果登录成功，检查是否为管理员并添加标志
                if (ok) {
                    int is_admin_user = is_admin(uid);
                    char resp[3] = { MSG_RESULT, 1, is_admin_user ? 1 : 0 };
                    
                    // 确保登录响应被完整发送
                    int sent = 0;
                    while (sent < 3) {
                        int s = send(client_fd, resp + sent, 3 - sent, 0);
                        if (s <= 0) {
                            if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                                continue;  // 暂时无法发送，重试
                            }
                            perror("send login response");
                            break;
                        }
                        sent += s;
                    }
                } else {
                    char resp[2] = { MSG_RESULT, 0 };
                    
                    // 确保登录响应被完整发送
                    int sent = 0;
                    while (sent < 2) {
                        int s = send(client_fd, resp + sent, 2 - sent, 0);
                        if (s <= 0) {
                            if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                                continue;  // 暂时无法发送，重试
                            }
                            perror("send login response");
                            break;
                        }
                        sent += s;
                    }
                }
            }
            else if (cmd == MSG_UPLOAD && uid >= 0) {
                char *filename = &buf[1];
                char *access_level = "private";
                
                printf("[SERVER] Upload request for file '%s' from UID=%d\n", filename, uid);
                
                // 检查是否有access_level字段（协议可扩展）
                if ((size_t)(strlen(filename) + 1) < (size_t)(n - 1)) {
                    access_level = filename + strlen(filename) + 1 + 8 + 16;
                    printf("[SERVER] Access level specified: '%s'\n", access_level);
                    if (strcmp(access_level, "public")!=0 && strcmp(access_level, "admin-only")!=0 && strcmp(access_level, "private")!=0)
                        access_level = "private";
                }
                
                uint64_t netlen;
                memcpy(&netlen, filename + strlen(filename) + 1, 8);
                size_t enc_len = ntohll(netlen);
                printf("[SERVER] Encrypted data length: %zu bytes\n", enc_len);
                
                unsigned char iv[16];
                memcpy(iv, filename + strlen(filename) + 1 + 8, 16);

                unsigned char *enc = (unsigned char*)
                    (filename + strlen(filename) + 1 + 8 + 16 + strlen(access_level) + 1);
                unsigned char *dec = malloc(enc_len);
                if (!dec) {
                    printf("[SERVER] Memory allocation failed for decryption buffer\n");
                    continue;
                }

                printf("[SERVER] Decrypting data...\n");
                unsigned char key[16] = {0};
                sm4_cbc_decrypt_wrapper(key, iv, enc, dec, enc_len);

                // 确保uploads目录存在
                struct stat st = {0};
                if (stat("uploads", &st) == -1) {
                    mkdir("uploads", 0700);
                    printf("[SERVER] Created 'uploads' directory\n");
                }

                // 检查文件名长度，防止路径缓冲区溢出
                if (strlen(filename) > 240) { // 预留足够空间给"uploads/"前缀和终止符
                    printf("[SERVER] Filename too long for upload: %s\n", filename);
                    free(dec);
                    continue;
                }

                char path[512]; // 增大缓冲区
                snprintf(path, sizeof(path), "uploads/%s", filename);
                printf("[SERVER] Writing file to: %s\n", path);
                
                int write_result = write_file(path, dec, enc_len);
                if (write_result < 0) {
                    printf("[SERVER] Failed to write file: %s\n", path);
                    free(dec);
                    continue;
                }
                
                int db_result = add_file_record(filename, path, uid, access_level);
                if (db_result < 0) {
                    printf("[SERVER] Failed to add file record to database\n");
                } else {
                    printf("[SERVER] File record added to database\n");
                }
                
                free(dec);

                // 立即发送ACK，确保客户端能收到
                char ack = MSG_UPLOAD_ACK;
                printf("[SERVER] Sending upload ACK\n");
                
                // 临时设置为阻塞模式以发送ACK
                int old_flags = fcntl(client_fd, F_GETFL, 0);
                fcntl(client_fd, F_SETFL, old_flags & ~O_NONBLOCK);
                
                // 设置发送超时
                struct timeval tv;
                tv.tv_sec = 5;  // 5秒超时
                tv.tv_usec = 0;
                setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                
                // 尝试多次发送ACK
                int ack_sent = 0;
                for (int retry = 0; retry < 5 && !ack_sent; retry++) {
                    if (retry > 0) {
                        printf("[SERVER] Retry %d: Sending ACK\n", retry);
                        // 短暂延迟后重试
                        usleep(200000);  // 200毫秒
                    }
                    
                    int send_result = send(client_fd, &ack, 1, 0);
                    if (send_result == 1) {
                        printf("[SERVER] Upload ACK sent successfully\n");
                        ack_sent = 1;
                    } else {
                        printf("[SERVER] Failed to send upload ACK: %s\n", strerror(errno));
                    }
                }
                
                // 恢复非阻塞模式
                fcntl(client_fd, F_SETFL, old_flags);
                
                if (!ack_sent) {
                    printf("[SERVER] Failed to send ACK after multiple attempts\n");
                }
                
                printf("[SERVER] Uploaded '%s' by UID=%d\n", filename, uid);
                
                // 日志
                struct sockaddr_in addr; socklen_t len=sizeof(addr);
                getpeername(client_fd, (struct sockaddr*)&addr, &len);
                char ip[32]={0}; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                add_log(uid, "", "upload", filename, ip);
            }
            else if (cmd == MSG_DOWNLOAD && uid >= 0) {
                uint32_t netfid;
                memcpy(&netfid, buf + 1, 4);
                int file_id = ntohl(netfid);
                char *filename = buf + 1 + 4;

                // 安全检查：确保filename字符串有效
                if (n <= 1 || strlen(filename) >= sizeof(buf) - 1) {
                    printf("[SERVER] Invalid download request: filename too long or missing\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 检查文件名长度，防止路径缓冲区溢出
                if (strlen(filename) > 240) { // 预留足够空间给"uploads/"前缀和终止符
                    printf("[SERVER] Filename too long: %s\n", filename);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                printf("[SERVER] Download request for file: %s\n", filename);
                
                // 构造文件路径
                char path[512]; // 增大缓冲区
                snprintf(path, sizeof(path), "uploads/%s", filename);
                
                // file_id=0时也做权限校验
                if (file_id == 0) {
                    // 通过文件名查file_id
                    sqlite3* db = NULL;
                    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
                        char nok = MSG_RESULT;
                        send(client_fd, &nok, 1, 0);
                        continue;
                    }
                    sqlite3_stmt* stmt = NULL;
                    int fid = 0;
                    if (db && sqlite3_prepare_v2(db, "SELECT file_id FROM files WHERE filename=?;", -1, &stmt, NULL)==SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, filename, -1, NULL);
                        if (sqlite3_step(stmt)==SQLITE_ROW) fid = sqlite3_column_int(stmt, 0);
                        sqlite3_finalize(stmt);
                    }
                    if (db) sqlite3_close(db);
                    if (fid == 0 || !check_file_permission(fid, uid)) {
                        char nok = MSG_RESULT;
                        send(client_fd, &nok, 1, 0);
                        printf("[SERVER] UID=%d denied download of file '%s'\n", uid, filename);
                        continue;
                    }
                } else if (!check_file_permission(file_id, uid)) {
                    char nok = MSG_RESULT;
                    send(client_fd, &nok, 1, 0);
                    printf("[SERVER] UID=%d denied download of file_id=%d\n", uid, file_id);
                    continue;
                }

                unsigned char *plain;
                ssize_t file_len = read_file(path, &plain);
                if (file_len < 0) continue;

                size_t pad = (16 - (file_len % 16)) % 16;
                size_t tot = file_len + pad;
                unsigned char *padded = malloc(tot);
                memcpy(padded, plain, file_len);
                memset(padded + file_len, pad, pad);

                unsigned char key[16] = {0}, iv[16] = {0};
                unsigned char *enc = malloc(tot);
                sm4_cbc_encrypt_wrapper(key, iv, padded, enc, tot);
                free(plain); free(padded);

                char ok = MSG_DOWNLOAD_OK;
                send(client_fd, &ok, 1, 0);
                uint64_t netlen2 = htonll(tot);
                send(client_fd, &netlen2, 8, 0);
                send(client_fd, iv, 16, 0);
                send(client_fd, enc, tot, 0);
                free(enc);

                char fin = MSG_DOWNLOAD_END;
                send(client_fd, &fin, 1, 0);
                printf("[SERVER] Sent '%s' to UID=%d\n", filename, uid);
                // 日志
                struct sockaddr_in addr; socklen_t addrlen=sizeof(addr);
                getpeername(client_fd, (struct sockaddr*)&addr, &addrlen);
                char ip[32]={0}; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                add_log(uid, "", "download", filename, ip);
            }
            else if (cmd == MSG_LIST_FILES && uid >= 0) {
                printf("[SERVER] User UID=%d requested file list\n", uid);
                char result[4096] = {0};
                list_user_files(uid, result, sizeof(result));  // 不使用返回值
                
                // 即使没有文件，也发送空的JSON数组
                char header[2] = { MSG_LIST_FILES_RESP, 1 };  // 始终返回成功
                printf("[SERVER] Sending file list response header [%02x %02x]\n", 
                       (unsigned char)header[0], (unsigned char)header[1]);
                
                // 确保头部被完整发送
                int sent = 0;
                while (sent < 2) {
                    int s = send(client_fd, header + sent, 2 - sent, 0);
                    if (s <= 0) {
                        if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                            continue;  // 暂时无法发送，重试
                        }
                        perror("send file list header");
                        break;
                    }
                    sent += s;
                }
                
                // 发送文件列表数据，即使是空数组
                size_t result_len = strlen(result);
                printf("[SERVER] Sending file list data: %zu bytes\n", result_len);
                
                if (result_len > 0) {
                    sent = 0;
                    while ((size_t)sent < result_len) {
                        int s = send(client_fd, result + sent, result_len - sent, 0);
                        if (s <= 0) {
                            if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                                continue;  // 暂时无法发送，重试
                            }
                            perror("send file list data");
                            break;
                        }
                        sent += s;
                    }
                    
                    if ((size_t)sent == result_len) {
                        printf("[SERVER] File list data sent successfully\n");
                    } else {
                        printf("[SERVER] Failed to send complete file list data: sent %d of %zu bytes\n", 
                               sent, result_len);
                    }
                } else {
                    printf("[SERVER] No file list data to send (empty array)\n");
                }
            }
            else if (cmd == MSG_LIST_LOGS && uid >= 0) {
                int isadmin = is_admin(uid);
                char result[4096] = {0};
                int n = list_logs(isadmin ? -1 : uid, isadmin, result, sizeof(result));
                char header[2] = { MSG_LIST_LOGS_RESP, (n >= 0) ? 1 : 0 };
                send(client_fd, header, 2, 0);
                if (n > 0) send(client_fd, result, strlen(result), 0);
            }
            else if (cmd == MSG_DELETE_FILE && uid >= 0) {
                char *filename = &buf[1];
                
                // 检查文件名长度，防止路径缓冲区溢出
                if (strlen(filename) > 240) { // 预留足够空间给"uploads/"前缀和终止符
                    printf("[SERVER] Filename too long for deletion: %s\n", filename);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                printf("[SERVER] User UID=%d requested to delete file '%s'\n", uid, filename);
                
                // 检查文件是否存在及用户是否有权限删除
                sqlite3* db = NULL;
                int file_id = 0;
                int owner_id = 0;
                char access_level[20] = {0};
                int can_delete = 0;
                
                if (sqlite3_open("secure_file_transfer.db", &db) == SQLITE_OK) {
                    sqlite3_stmt* stmt = NULL;
                    
                    // 获取文件ID、所有者ID和访问权限
                    if (sqlite3_prepare_v2(db, "SELECT file_id, user_id, access_level FROM files WHERE filename=?;", -1, &stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, filename, -1, NULL);
                        if (sqlite3_step(stmt) == SQLITE_ROW) {
                            file_id = sqlite3_column_int(stmt, 0);
                            owner_id = sqlite3_column_int(stmt, 1);
                            const char* access = (const char*)sqlite3_column_text(stmt, 2);
                            if (access) {
                                strncpy(access_level, access, sizeof(access_level)-1);
                            }
                        }
                        sqlite3_finalize(stmt);
                    }
                    
                    // 检查用户是否是管理员
                    int is_admin_user = is_admin(uid);
                    
                    // 删除权限规则：
                    // 1. 管理员可以删除任何文件
                    // 2. 普通用户只能删除自己的文件
                    // 3. 普通用户不能删除admin-only文件，即使是自己上传的
                    if (is_admin_user) {
                        can_delete = 1; // 管理员可以删除任何文件
                        printf("[SERVER] Admin user UID=%d has permission to delete file '%s'\n", uid, filename);
                    } else if (uid == owner_id) {
                        if (strcmp(access_level, "admin-only") == 0) {
                            can_delete = 0; // 普通用户不能删除admin-only文件，即使是自己上传的
                            printf("[SERVER] User UID=%d cannot delete admin-only file '%s'\n", uid, filename);
                        } else {
                            can_delete = 1; // 普通用户可以删除自己的文件
                            printf("[SERVER] User UID=%d has permission to delete own file '%s'\n", uid, filename);
                        }
                    } else {
                        can_delete = 0; // 普通用户不能删除别人的文件
                        printf("[SERVER] User UID=%d cannot delete file '%s' owned by UID=%d\n", uid, filename, owner_id);
                    }
                    
                    sqlite3_close(db);
                }
                
                // 如果没有权限或文件不存在
                if (file_id == 0 || !can_delete) {
                    printf("[SERVER] UID=%d denied deletion of file '%s'\n", uid, filename);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 从文件系统删除文件
                char path[512];
                snprintf(path, sizeof(path), "uploads/%s", filename);
                
                // 如果文件存在于文件系统，则删除
                if (unlink(path) == 0) {
                    printf("[SERVER] File '%s' deleted from filesystem\n", path);
                } else {
                    // 文件可能不在文件系统中（例如，只存在于数据库记录中），我们仍然继续
                    printf("[SERVER] Could not delete file from filesystem: %s (errno: %s)\n", path, strerror(errno));
                }
                
                // 从数据库删除文件记录
                if (delete_file_record(file_id) == 0) {
                    printf("[SERVER] File record with ID %d deleted successfully\n", file_id);
                    char resp[2] = { MSG_RESULT, 1 }; // 成功
                    send(client_fd, resp, 2, 0);

                    // 记录日志
                    struct sockaddr_in addr;
                    socklen_t len = sizeof(addr);
                    getpeername(client_fd, (struct sockaddr*)&addr, &len);
                    char ip[32] = {0};
                    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                    add_log(uid, "", "delete_file", filename, ip);
                } else {
                    printf("[SERVER] Failed to delete file record with ID %d\n", file_id);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                }
                continue; // 确保在处理完删除请求后，服务器继续监听
            }
            else if (cmd == MSG_DELETE_USER && uid >= 0) {
                // 只有管理员可以删除用户
                if (!is_admin(uid)) {
                    printf("[SERVER] Non-admin user UID=%d attempted to delete a user\n", uid);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                char *username = &buf[1];
                printf("[SERVER] Admin UID=%d requested to delete user '%s'\n", uid, username);
                
                // 不能删除自己
                char admin_username[64] = {0};
                char* admin_name = get_username_by_id(uid, admin_username, sizeof(admin_username));
                if (admin_name && strcmp(username, admin_name) == 0) {
                    printf("[SERVER] Admin UID=%d attempted to delete themselves\n", uid);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 获取要删除用户的ID
                int target_uid = get_user_id_by_name(username);
                if (target_uid < 0) {
                    printf("[SERVER] User '%s' not found\n", username);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 删除用户
                int result = delete_user(target_uid);
                
                // 响应结果
                char resp[2] = { MSG_RESULT, (result == 0) ? 1 : 0 };
                send(client_fd, resp, 2, 0);
                
                // 记录日志
                if (result == 0) {
                    struct sockaddr_in addr;
                    socklen_t len = sizeof(addr);
                    getpeername(client_fd, (struct sockaddr*)&addr, &len);
                    char ip[32] = {0};
                    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                    
                    char details[300];
                    snprintf(details, sizeof(details), "删除用户 %s", username);
                    char username_buf[64] = {0};
                    char* admin_name = get_username_by_id(uid, username_buf, sizeof(username_buf));
                    // 如果无法获取用户名，使用用户ID作为备用
                    if (admin_name == NULL) {
                        snprintf(username_buf, sizeof(username_buf), "UID:%d", uid);
                        admin_name = username_buf;
                    }
                    add_log(uid, admin_name, "delete_user", details, ip);
                    printf("[SERVER] User '%s' deleted by admin UID=%d\n", username, uid);
                } else {
                    printf("[SERVER] Failed to delete user '%s', error code: %d\n", username, result);
                }
            }
            else if (cmd == MSG_SEARCH_FILES && uid >= 0) {
                char *keyword = &buf[1];
                
                // 安全检查：确保关键词是有效的字符串
                size_t len = n - 1; // 消息总长度减去命令字节
                if (len <= 0 || len >= sizeof(buf) - 1) {
                    printf("[SERVER] Invalid search keyword length\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 确保关键词以 null 结尾
                buf[n] = '\0';
                
                printf("[SERVER] Search files request with keyword: %s\n", keyword);
                
                // 构建SQL查询
                sqlite3 *db = NULL;
                if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
                    printf("[SERVER] Failed to open database\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 修改SQL查询，不依赖is_admin列
                const char *sql = "SELECT f.file_id, f.filename, f.upload_time, f.access_level, u.username "
                                 "FROM files f JOIN users u ON f.user_id = u.user_id "
                                 "WHERE f.filename LIKE ? AND "
                                 "(f.user_id = ? OR f.access_level = 'public' OR "
                                 "(f.access_level = 'admin-only' AND ?))";
                
                sqlite3_stmt *stmt = NULL;
                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
                    printf("[SERVER] Failed to prepare search statement: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 构建LIKE模式
                char pattern[256] = {0};
                snprintf(pattern, sizeof(pattern), "%%%s%%", keyword); // %keyword%
                
                sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 2, uid);
                sqlite3_bind_int(stmt, 3, is_admin(uid) ? 1 : 0); // 直接使用is_admin函数判断
                
                // 构建JSON结果 - 使用更简单明确的方式生成JSON
                char result[4096] = {0};
                int offset = 0;
                int count = 0;
                
                // 开始JSON数组 - 确保这是一个标准JSON数组
                offset += snprintf(result + offset, sizeof(result) - offset, "[");
                
                // 执行查询并收集结果
                while (sqlite3_step(stmt) == SQLITE_ROW && (size_t)offset < sizeof(result) - 256) {
                    // 添加逗号分隔符（对第2个及以后的对象）
                    if (count > 0) {
                        offset += snprintf(result + offset, sizeof(result) - offset, ",");
                    }
                    
                    int file_id = sqlite3_column_int(stmt, 0);
                    const char *filename = (const char *)sqlite3_column_text(stmt, 1);
                    const char *upload_time = (const char *)sqlite3_column_text(stmt, 2);
                    const char *access_level = (const char *)sqlite3_column_text(stmt, 3);
                    const char *owner = (const char *)sqlite3_column_text(stmt, 4);
                    
                    // 安全处理NULL值
                    if (!filename) filename = "";
                    if (!upload_time) upload_time = "";
                    if (!access_level) access_level = "private";
                    if (!owner) owner = "unknown";
                    
                    // 转义JSON字符串中的特殊字符
                    char escaped_filename[512] = {0};
                    char escaped_upload_time[128] = {0};
                    char escaped_access_level[128] = {0};
                    char escaped_owner[128] = {0};
                    
                    escape_json_string(filename, escaped_filename, sizeof(escaped_filename));
                    escape_json_string(upload_time, escaped_upload_time, sizeof(escaped_upload_time));
                    escape_json_string(access_level, escaped_access_level, sizeof(escaped_access_level));
                    escape_json_string(owner, escaped_owner, sizeof(escaped_owner));
                    
                    // 避免缓冲区溢出
                    int remaining = sizeof(result) - offset - 1;
                    if (remaining <= 0) break;
                    
                    // 确保生成标准的JSON对象
                    offset += snprintf(result + offset, remaining,
                                     "{\"file_id\":%d,\"filename\":\"%s\",\"upload_time\":\"%s\","
                                     "\"access_level\":\"%s\",\"owner\":\"%s\"}",
                                     file_id, escaped_filename, escaped_upload_time, 
                                     escaped_access_level, escaped_owner);
                    count++;
                }
                
                // 确保不会溢出，并正确关闭JSON数组
                if ((size_t)offset < sizeof(result) - 2) {
                    offset += snprintf(result + offset, sizeof(result) - offset, "]");
                } else {
                    // 如果结果太长，截断并添加结束括号
                    result[sizeof(result) - 2] = ']';
                    result[sizeof(result) - 1] = '\0';
                }
                
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                
                // 打印最终的JSON，便于调试
                printf("[SERVER] Search result JSON: %s\n", result);
                
                // 使用单一发送操作，确保整个JSON作为一个完整包发送
                // 发送响应
                char header[2] = { MSG_LIST_FILES_RESP, 1 };
                if (send(client_fd, header, 2, 0) != 2) {
                    printf("[SERVER] Failed to send search response header\n");
                    continue;
                }
                
                size_t result_len = strlen(result);
                int sent = send(client_fd, result, result_len, 0);
                if (sent != (ssize_t)result_len) {
                    printf("[SERVER] Failed to send search results: sent %d of %lu bytes\n", 
                           sent, result_len);
                    continue;
                }
                
                printf("[SERVER] Search returned %d results\n", count);
            }
            else if (cmd == MSG_CHANGE_PASS) {
                // 用户必须先登录
                if (uid < 0) {
                    printf("[SERVER] Password change request from unauthenticated user\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                char *username = &buf[1];
                
                // 安全检查：确保username字符串有效
                if (n <= 1 || strlen(username) >= sizeof(buf) - 1) {
                    printf("[SERVER] Invalid password change request: username too long or missing\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 安全地找到旧密码字段
                size_t username_len = strlen(username);
                if ((size_t)n > 1 + username_len + 1) {
                    char *old_password = username + username_len + 1;
                    
                    // 确保旧密码字符串有效
                    size_t old_password_len = strlen(old_password);
                    if ((size_t)n > 1 + username_len + 1 + old_password_len + 1) {
                        char *new_password = old_password + old_password_len + 1;
                        
                        printf("[SERVER] Password change request for user '%s'\n", username);
                        
                        // 验证旧密码
                        int user_id = get_user_id_by_name(username);
                        if (user_id < 0 || !verify_password(user_id, old_password)) {
                            printf("[SERVER] Invalid old password for user '%s'\n", username);
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 验证新密码格式
                        if (strlen(new_password) < 6) {
                            printf("[SERVER] New password too short for user '%s'\n", username);
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 更新密码
                        int result = update_password(user_id, new_password);
                        char resp[2] = { MSG_RESULT, (result == 0) ? 1 : 0 };
                        send(client_fd, resp, 2, 0);
                        
                        // 记录日志
                        struct sockaddr_in addr; socklen_t len=sizeof(addr);
                        getpeername(client_fd, (struct sockaddr*)&addr, &len);
                        char ip[32]={0}; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                        add_log(uid, username, "change_password", "", ip);
                        printf("[SERVER] Password changed for user '%s'\n", username);
                    } else {
                        printf("[SERVER] Invalid password change request: old password missing\n");
                        char resp[2] = { MSG_RESULT, 0 }; // 失败
                        send(client_fd, resp, 2, 0);
                        continue;
                    }
                } else {
                    printf("[SERVER] Invalid password change request: old password missing\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
            }
            else if (cmd == MSG_USER_MANAGE && buf[1] == 2) {
                // 用户必须先登录
                if (uid < 0) {
                    printf("[SERVER] Password change request from unauthenticated user\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                char *username = &buf[2];
                
                // 安全检查：确保username字符串有效
                if (n <= 2 || strlen(username) >= sizeof(buf) - 2) {
                    printf("[SERVER] Invalid password change request: username too long or missing\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 安全地找到旧密码字段
                size_t username_len = strlen(username);
                if ((size_t)n > 2 + username_len + 1) {
                    char *old_password = username + username_len + 1;
                    
                    // 确保旧密码字符串有效
                    size_t old_password_len = strlen(old_password);
                    if ((size_t)n > 2 + username_len + 1 + old_password_len + 1) {
                        char *new_password = old_password + old_password_len + 1;
                        
                        printf("[SERVER] Password change request for user '%s'\n", username);
                        
                        // 验证旧密码
                        int user_id = get_user_id_by_name(username);
                        if (user_id < 0 || !verify_password(user_id, old_password)) {
                            printf("[SERVER] Invalid old password for user '%s'\n", username);
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 验证新密码格式
                        if (strlen(new_password) < 6) {
                            printf("[SERVER] New password too short for user '%s'\n", username);
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 更新密码
                        int result = update_password(user_id, new_password);
                        char resp[2] = { MSG_RESULT, (result == 0) ? 1 : 0 };
                        send(client_fd, resp, 2, 0);
                        
                        // 记录日志
                        struct sockaddr_in addr; socklen_t len=sizeof(addr);
                        getpeername(client_fd, (struct sockaddr*)&addr, &len);
                        char ip[32]={0}; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                        add_log(uid, username, "change_password", "", ip);
                        printf("[SERVER] Password changed for user '%s'\n", username);
                    } else {
                        printf("[SERVER] Invalid password change request: old password missing\n");
                        char resp[2] = { MSG_RESULT, 0 }; // 失败
                        send(client_fd, resp, 2, 0);
                        continue;
                    }
                } else {
                    printf("[SERVER] Invalid password change request: old password missing\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
            }
            else if (cmd == MSG_USER_MANAGE && buf[1] == 3 && uid >= 0) {
                char *keyword = &buf[2];
                printf("[SERVER] Search files request with keyword: %s\n", keyword);
                
                // 构建SQL查询
                sqlite3 *db = NULL;
                if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
                    printf("[SERVER] Failed to open database\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 准备SQL查询 - 根据用户权限返回可见文件
                const char *sql = "SELECT f.file_id, f.filename, f.upload_time, f.access_level, u.username "
                                 "FROM files f JOIN users u ON f.user_id = u.user_id "
                                 "WHERE f.filename LIKE ? AND "
                                 "(f.user_id = ? OR f.access_level = 'public' OR "
                                 "(f.access_level = 'admin-only' AND ?))";
                
                sqlite3_stmt *stmt = NULL;
                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
                    printf("[SERVER] Failed to prepare search statement: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 构建LIKE模式
                char pattern[256];
                snprintf(pattern, sizeof(pattern), "%%%s%%", keyword); // %keyword%
                
                sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 2, uid);
                sqlite3_bind_int(stmt, 3, is_admin(uid) ? 1 : 0); // 直接使用is_admin函数判断
                
                // 构建JSON结果
                char result[4096] = {0};
                int offset = 0;
                int count = 0;
                
                // 开始JSON数组
                offset += snprintf(result + offset, sizeof(result) - offset, "[");
                
                // 执行查询并收集结果
                while (sqlite3_step(stmt) == SQLITE_ROW && (size_t)offset < sizeof(result) - 128) {
                    if (count > 0) {
                        offset += snprintf(result + offset, sizeof(result) - offset, ",");
                    }
                    
                    int file_id = sqlite3_column_int(stmt, 0);
                    const char *filename = (const char *)sqlite3_column_text(stmt, 1);
                    const char *upload_time = (const char *)sqlite3_column_text(stmt, 2);
                    const char *access_level = (const char *)sqlite3_column_text(stmt, 3);
                    const char *owner = (const char *)sqlite3_column_text(stmt, 4);
                    
                    // 安全处理NULL值
                    if (!filename) filename = "";
                    if (!upload_time) upload_time = "";
                    if (!access_level) access_level = "private";
                    if (!owner) owner = "unknown";
                    
                    offset += snprintf(result + offset, sizeof(result) - offset,
                                      "{\"file_id\":%d,\"filename\":\"%s\",\"upload_time\":\"%s\","
                                      "\"access_level\":\"%s\",\"owner\":\"%s\"}",
                                      file_id, filename, upload_time, access_level, owner);
                    count++;
                }
                
                offset += snprintf(result + offset, sizeof(result) - offset, "]");
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                
                // 发送响应
                char header[2] = { MSG_LIST_FILES_RESP, 1 };
                send(client_fd, header, 2, 0);
                send(client_fd, result, strlen(result), 0);
                
                printf("[SERVER] Search returned %d results\n", count);
            }
            else if (cmd == MSG_USER_MANAGE && uid >= 0) {
                // 检查用户是否是管理员
                if (!is_admin(uid)) {
                    printf("[SERVER] Non-admin user UID=%d attempted to access user management\n", uid);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 检查是否有子命令
                if (n > 1) {
                    char subcmd = buf[1];
                    
                    // 子命令1：修改用户角色
                    if (subcmd == 1 && n > 2) {
                        char *username = &buf[2];
                        char *new_role = username + strlen(username) + 1;
                        
                        printf("[SERVER] Admin UID=%d changing role of user '%s' to '%s'\n", 
                               uid, username, new_role);
                        
                        // 验证角色值
                        if (strcmp(new_role, "user") != 0 && strcmp(new_role, "admin") != 0) {
                            printf("[SERVER] Invalid role '%s'\n", new_role);
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 只有admin用户才能管理用户
                        char admin_username[64] = {0};
                        if (!get_username_by_id(uid, admin_username, sizeof(admin_username)) || 
                            strcasecmp(admin_username, "admin") != 0) {
                            printf("[SERVER] Non-admin user '%s' attempted to change user role\n", 
                                   admin_username[0] ? admin_username : "unknown");
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 不能修改自己的角色
                        if (strcmp(new_role, "admin") == 0) {
                            printf("[SERVER] Admin UID=%d attempted to change their own role\n", uid);
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 获取目标用户ID
                        int target_uid = get_user_id(username);
                        if (target_uid < 0) {
                            printf("[SERVER] User '%s' not found\n", username);
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 不允许修改admin用户的角色
                        if (strcasecmp(username, "admin") == 0) {
                            printf("[SERVER] Attempted to change role of admin user, which is not allowed\n");
                            char resp[2] = { MSG_RESULT, 0 }; // 失败
                            send(client_fd, resp, 2, 0);
                            continue;
                        }
                        
                        // 更新用户角色
                        sqlite3* db = NULL;
                        int result = -1;
                        
                        if (sqlite3_open("secure_file_transfer.db", &db) == SQLITE_OK) {
                            // 检查数据库表结构
                            int has_is_admin_column = 0;
                            int has_role_column = 0;
                            sqlite3_stmt* check_stmt = NULL;
                            const char* check_sql = "PRAGMA table_info(users);";
                            
                            if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) == SQLITE_OK) {
                                while (sqlite3_step(check_stmt) == SQLITE_ROW) {
                                    const char* column_name = (const char*)sqlite3_column_text(check_stmt, 1);
                                    if (column_name && strcmp(column_name, "is_admin") == 0) {
                                        has_is_admin_column = 1;
                                    }
                                    if (column_name && strcmp(column_name, "role") == 0) {
                                        has_role_column = 1;
                                    }
                                }
                                sqlite3_finalize(check_stmt);
                            }
                            
                            sqlite3_stmt* stmt = NULL;
                            const char* sql = NULL;
                            
                            // 根据表结构选择更新语句
                            if (has_is_admin_column) {
                                // 使用is_admin字段 - 普通用户的is_admin始终为0
                                sql = "UPDATE users SET is_admin = 0 WHERE user_id = ?;";
                                
                                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                                    sqlite3_bind_int(stmt, 1, target_uid);
                                    result = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
                                    sqlite3_finalize(stmt);
                                }
                            } 
                            
                            // 如果存在role列，也更新它
                            if (has_role_column) {
                                sql = "UPDATE users SET role = 'user' WHERE user_id = ?;";
                                
                                if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                                    sqlite3_bind_int(stmt, 1, target_uid);
                                    int role_result = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
                                    sqlite3_finalize(stmt);
                                    
                                    // 如果前面的更新失败但这个成功，设置结果为成功
                                    if (result != 0) {
                                        result = role_result;
                                    }
                                }
                            }
                            
                            // 如果两个列都不存在，返回错误
                            if (!has_is_admin_column && !has_role_column) {
                                printf("[SERVER] Error: Neither is_admin nor role column exists in users table\n");
                                result = -1;
                            }
                            
                            sqlite3_close(db);
                        }
                        
                        // 发送响应
                        char resp[2] = { MSG_RESULT, (result == 0) ? 1 : 0 };
                        send(client_fd, resp, 2, 0);
                        
                        // 记录日志
                        if (result == 0) {
                            struct sockaddr_in addr; socklen_t len=sizeof(addr);
                            getpeername(client_fd, (struct sockaddr*)&addr, &len);
                            char ip[32]={0}; inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                            
                            char log_details[300];
                            snprintf(log_details, sizeof(log_details), "将用户 %s 角色设置为 %s", username, new_role);
                            char username_buf[64] = {0};
                            char* admin_name = get_username_by_id(uid, username_buf, sizeof(username_buf));
                            // 如果无法获取用户名，使用用户ID作为备用
                            if (admin_name == NULL) {
                                snprintf(username_buf, sizeof(username_buf), "UID:%d", uid);
                                admin_name = username_buf;
                            }
                            add_log(uid, admin_name, "change_role", log_details, ip);
                            printf("[SERVER] User '%s' role changed to '%s' by admin UID=%d\n", username, new_role, uid);
                        } else {
                            printf("[SERVER] Failed to change role of user '%s'\n", username);
                        }
                    }
                    // 其他子命令...
                } else {
                    // 默认操作：获取用户列表
                    printf("[SERVER] Admin UID=%d requested user list\n", uid);
                    
                    // 验证是否为admin用户
                    char admin_username[64] = {0};
                    if (!get_username_by_id(uid, admin_username, sizeof(admin_username)) || 
                        strcasecmp(admin_username, "admin") != 0) {
                        printf("[SERVER] Non-admin user attempted to access user list\n");
                        char resp[2] = { MSG_USER_MANAGE, 0 }; // 失败
                        send(client_fd, resp, 2, 0);
                        continue;
                    }
                    
                    sqlite3* db = NULL;
                    sqlite3_stmt* stmt = NULL;
                    char result[4096] = {0};
                    int offset = 0;
                    int count = 0;
                    
                    // 打开数据库
                    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
                        printf("[SERVER] Failed to open database for user list\n");
                        char resp[2] = { MSG_USER_MANAGE, 0 }; // 失败
                        send(client_fd, resp, 2, 0);
                        continue;
                    }
                    
                    // 构建查询 - 获取所有用户
                    const char* sql = NULL;
                    
                    // 检查数据库表结构
                    int has_is_admin_column = 0;
                    sqlite3_stmt* check_stmt = NULL;
                    const char* check_sql = "PRAGMA table_info(users);";
                    
                    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) == SQLITE_OK) {
                        while (sqlite3_step(check_stmt) == SQLITE_ROW) {
                            const char* column_name = (const char*)sqlite3_column_text(check_stmt, 1);
                            if (column_name && strcmp(column_name, "is_admin") == 0) {
                                has_is_admin_column = 1;
                            }
                        }
                        sqlite3_finalize(check_stmt);
                    }
                    
                    // 根据表结构选择查询语句
                    if (has_is_admin_column) {
                        sql = "SELECT user_id, username, register_time, is_admin FROM users ORDER BY user_id;";
                    } else {
                        // 检查是否存在role列
                        int has_role_column = 0;
                        sqlite3_stmt* role_check_stmt = NULL;
                        const char* role_check_sql = "PRAGMA table_info(users);";
                        
                        if (sqlite3_prepare_v2(db, role_check_sql, -1, &role_check_stmt, NULL) == SQLITE_OK) {
                            while (sqlite3_step(role_check_stmt) == SQLITE_ROW) {
                                const char* column_name = (const char*)sqlite3_column_text(role_check_stmt, 1);
                                if (column_name && strcmp(column_name, "role") == 0) {
                                    has_role_column = 1;
                                    break;
                                }
                            }
                            sqlite3_finalize(role_check_stmt);
                        }
                        
                        if (has_role_column) {
                            sql = "SELECT user_id, username, register_time, role FROM users ORDER BY user_id;";
                        } else {
                            // 如果既没有is_admin也没有role列，只查询基本信息
                            sql = "SELECT user_id, username, register_time FROM users ORDER BY user_id;";
                        }
                    }
                    
                    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
                        printf("[SERVER] Failed to prepare user list query: %s\n", sqlite3_errmsg(db));
                        sqlite3_close(db);
                        char resp[2] = { MSG_USER_MANAGE, 0 }; // 失败
                        send(client_fd, resp, 2, 0);
                        continue;
                    }
                    
                    // 开始构建JSON数组
                    offset += snprintf(result + offset, sizeof(result) - offset, "[");
                    
                    // 执行查询并收集结果
                    while (sqlite3_step(stmt) == SQLITE_ROW && (size_t)offset < sizeof(result) - 128) {
                        if (count > 0) {
                            offset += snprintf(result + offset, sizeof(result) - offset, ",");
                        }
                        
                        int user_id = sqlite3_column_int(stmt, 0);
                        const char* username = (const char*)sqlite3_column_text(stmt, 1);
                        const char* register_time = (const char*)sqlite3_column_text(stmt, 2);
                        
                        // 根据表结构处理管理员状态
                        bool is_admin_val = false;
                        if (has_is_admin_column) {
                            is_admin_val = sqlite3_column_int(stmt, 3) != 0;
                        } else if (sqlite3_column_count(stmt) > 3) {
                            const char* role = (const char*)sqlite3_column_text(stmt, 3);
                            is_admin_val = (role && strcmp(role, "admin") == 0);
                        } else {
                            // 如果没有管理员相关列，检查用户名是否为admin
                            is_admin_val = (username && strcasecmp(username, "admin") == 0);
                        }
                        
                        if (!username) username = "";
                        if (!register_time) register_time = "";
                        
                        offset += snprintf(result + offset, sizeof(result) - offset,
                            "{\"user_id\":%d,\"username\":\"%s\",\"register_time\":\"%s\",\"is_admin\":%s}",
                            user_id, username, register_time, is_admin_val ? "true" : "false");
                        
                        count++;
                    }
                    
                    // 完成JSON数组
                    snprintf(result + offset, sizeof(result) - offset, "]");
                    
                    // 清理资源
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                    
                    // 发送响应头
                    char header[2] = { MSG_USER_MANAGE, 1 }; // 成功
                    send(client_fd, header, 2, 0);
                    
                    // 发送用户列表
                    send(client_fd, result, strlen(result), 0);
                    
                    printf("[SERVER] Sent user list to admin UID=%d, found %d users\n", uid, count);
                }
            }
            else if (cmd == MSG_LIST_LOGS) {
                // 处理获取日志请求
                if (uid > 0) {
                    printf("[SERVER] User UID=%d requested logs\n", uid);
                    handle_get_logs_request(client_fd, uid);
                } else {
                    printf("[SERVER] Unauthenticated user requested logs, rejected\n");
                    char header[2] = {MSG_LIST_LOGS_RESP, 0}; // 0表示失败
                    send(client_fd, header, 2, 0);
                }
            }
            else if (cmd == MSG_SM2_PUBKEY) {
                // 处理客户端上传的SM2公钥
                char *pubkey_hex = &buf[1];
                printf("[SERVER] Received SM2 pubkey from client: %.16s...\n", pubkey_hex);
                
                // 获取当前用户ID
                if (uid <= 0) {
                    printf("[SERVER] Error: No logged in user for pubkey upload\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 保存用户公钥到数据库
                sqlite3 *db = NULL;
                sqlite3_stmt *stmt = NULL;
                int rc;
                
                rc = sqlite3_open("secure_file_transfer.db", &db);
                if (rc != SQLITE_OK) {
                    printf("[SERVER] Cannot open database: %s\n", sqlite3_errmsg(db));
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    sqlite3_close(db);
                    continue;
                }
                
                // 查询用户是否已有公钥
                const char *check_sql = "SELECT 1 FROM users WHERE user_id = ? AND sm2_pubkey IS NOT NULL;";
                rc = sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL);
                if (rc != SQLITE_OK) {
                    printf("[SERVER] SQL prepare error: %s\n", sqlite3_errmsg(db));
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    sqlite3_close(db);
                    continue;
                }
                
                sqlite3_bind_int(stmt, 1, uid);
                rc = sqlite3_step(stmt);
                int has_pubkey = (rc == SQLITE_ROW);
                sqlite3_finalize(stmt);
                
                // 更新或插入公钥
                const char *sql = has_pubkey 
                    ? "UPDATE users SET sm2_pubkey = ? WHERE user_id = ?;"
                    : "UPDATE users SET sm2_pubkey = ? WHERE user_id = ?;";
                
                rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
                if (rc != SQLITE_OK) {
                    printf("[SERVER] SQL prepare error: %s\n", sqlite3_errmsg(db));
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    sqlite3_close(db);
                    continue;
                }
                
                sqlite3_bind_text(stmt, 1, pubkey_hex, -1, SQLITE_STATIC);
                sqlite3_bind_int(stmt, 2, uid);
                
                rc = sqlite3_step(stmt);
                if (rc != SQLITE_DONE) {
                    printf("[SERVER] SQL error: %s\n", sqlite3_errmsg(db));
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                } else {
                    printf("[SERVER] Saved SM2 pubkey for user ID %d\n", uid);
                    char resp[2] = { MSG_RESULT, 1 }; // 成功
                    send(client_fd, resp, 2, 0);
                }
                
                sqlite3_finalize(stmt);
                sqlite3_close(db);
            }
            else if (cmd == MSG_SM2_KEYX) {
                // 处理密钥交换请求
                char *client_pubkey = &buf[1];
                printf("[SERVER] Received key exchange request with pubkey: %.16s...\n", client_pubkey);
                
                // 生成服务器的SM2密钥对
                char server_privkey[65] = {0};
                char server_pubkey[131] = {0};
                if (sm2_generate_keypair(server_privkey, server_pubkey) != 0) {
                    printf("[SERVER] Failed to generate SM2 key pair\n");
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 响应客户端，包含服务器公钥
                char resp[134]; // MSG_RESULT(1) + 成功标志(1) + 公钥(131) + 额外空间(1)
                resp[0] = MSG_RESULT;
                resp[1] = 1; // 成功
                strcpy(&resp[2], server_pubkey);
                
                if (send(client_fd, resp, 2 + strlen(server_pubkey) + 1, 0) <= 0) {
                    printf("[SERVER] Failed to send key exchange response\n");
                    continue;
                }
                
                // 生成共享密钥（这个密钥会在服务器端暂存，用于后续通信）
                uint8_t shared_key[16] = {0};
                if (sm2_key_exchange(server_privkey, server_pubkey, client_pubkey, 
                                    shared_key, sizeof(shared_key)) != 0) {
                    printf("[SERVER] Failed to generate shared key\n");
                    continue;
                }
                
                printf("[SERVER] Successfully established shared key with client\n");
                // 注意：实际实现中，应该将共享密钥保存，用于后续通信的加密
            }
            else if (cmd == MSG_SM2_VERIFY) {
                // 处理签名验证请求
                int offset = 1;
                
                // 读取数据长度
                uint32_t data_len = ntohl(*(uint32_t*)(&buf[offset]));
                offset += 4;
                
                // 验证数据长度
                if (data_len > sizeof(buf) - offset) {
                    printf("[SERVER] Data length too large: %u\n", data_len);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 提取数据
                uint8_t *data = (uint8_t*)&buf[offset];
                offset += data_len;
                
                // 读取签名长度
                uint32_t sig_len = ntohl(*(uint32_t*)(&buf[offset]));
                offset += 4;
                
                // 验证签名长度
                if (sig_len > sizeof(buf) - offset) {
                    printf("[SERVER] Signature length too large: %u\n", sig_len);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 提取签名
                char *signature = &buf[offset];
                offset += sig_len;
                
                // 读取公钥长度
                uint32_t pubkey_len = ntohl(*(uint32_t*)(&buf[offset]));
                offset += 4;
                
                // 验证公钥长度
                if (pubkey_len > sizeof(buf) - offset) {
                    printf("[SERVER] Pubkey length too large: %u\n", pubkey_len);
                    char resp[2] = { MSG_RESULT, 0 }; // 失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 提取公钥
                char *pubkey = &buf[offset];
                
                // 确保公钥和签名是C风格字符串
                signature[sig_len] = '\0';
                pubkey[pubkey_len] = '\0';
                
                // 验证签名
                int verify_result = sm2_verify_signature(
                    data, data_len, pubkey, signature);
                
                // 返回验证结果
                char resp[2] = { MSG_RESULT, verify_result == 1 ? 1 : 0 };
                send(client_fd, resp, 2, 0);
                
                printf("[SERVER] Signature verification result: %s\n", 
                      verify_result == 1 ? "valid" : "invalid");
            }
            else if (cmd == MSG_LIST_LOGS) {
                // 处理获取日志请求
                if (uid > 0) {
                    printf("[SERVER] User UID=%d requested logs\n", uid);
                    handle_get_logs_request(client_fd, uid);
                } else {
                    printf("[SERVER] Unauthenticated user requested logs, rejected\n");
                    char header[2] = {MSG_LIST_LOGS_RESP, 0}; // 0表示失败
                    send(client_fd, header, 2, 0);
                }
            }
            // 其他命令忽略
        }
    }

    close(client_fd);
    printf("[SERVER] Connection closed\n");
}

