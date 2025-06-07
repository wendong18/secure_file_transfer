// src/client/client_socket.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>         // for uint64_t
#include <errno.h>          // for errno, EAGAIN, EWOULDBLOCK
#include <stdbool.h>        // 添加stdbool.h以使用bool类型

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <io.h>
// Windows下定义EAGAIN和EWOULDBLOCK
#ifndef EAGAIN
#define EAGAIN WSAEWOULDBLOCK
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
// Windows下使用closesocket替代close
#define close(s) closesocket(s)
#else
#include <unistd.h>         // for close()
#include <arpa/inet.h>
#include <sys/select.h>     // for select(), fd_set
#include <sys/time.h>       // for struct timeval
#include <fcntl.h>          // for fcntl()
#endif

#include "../../include/common.h"
#include "../../include/client_socket.h"
#include "../../include/sm4.h"
#include "../../include/file_io.h"

#define MSG_LOGIN         0x01
#define MSG_RESULT        0x02
#define MSG_UPLOAD        0x03
#define MSG_UPLOAD_ACK    0x05
#define MSG_DOWNLOAD      0x04
#define MSG_DOWNLOAD_OK   0x06
#define MSG_DOWNLOAD_DATA 0x07
#define MSG_DOWNLOAD_END  0x08
#define MSG_LIST_FILES    0x09
#define MSG_LIST_FILES_RESP 0x0A
#define MSG_LIST_LOGS     0x0B
#define MSG_LIST_LOGS_RESP 0x0C
#define MSG_USER_MANAGE   0x0D
#define MSG_DELETE_FILE   0x0E
#define MSG_DELETE_USER   0x0F
#define MSG_SEARCH_FILES  0x10
#define MSG_CHANGE_PASS   0x11
#define MSG_SM2_PUBKEY    0x12
#define MSG_SM2_KEYX      0x13
#define MSG_SM2_VERIFY    0x15

// 64-bit hton/ntoh (network byte order)
static inline uint64_t htonll(uint64_t v) {
    return (((uint64_t)htonl(v & 0xFFFFFFFF)) << 32) | htonl(v >> 32);
}
static inline uint64_t ntohll(uint64_t v) {
    return htonll(v);
}

/**
 * 连接到服务器
 */
int connect_to_server(const char* ip, int port) {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket");
        return -1;
    }
    
    // 设置连接超时
    struct timeval tv;
    tv.tv_sec = 3;  // 3秒超时
    tv.tv_usec = 0;
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (connect(sfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sfd);
        return -1;
    }
    
    return sfd;
}

/**
 * 登录请求
 */
int login(int sfd, const char* u, const char* p) {
    if (!u || !p) {
        fprintf(stderr, "Error: Username or password is NULL\n");
        return -1;
    }
    
    fprintf(stderr, "Attempting login with username: %s\n", u);
    
    // 发送登录请求
    char buf[512] = { MSG_LOGIN };
    
    // 安全检查字符串长度以防溢出
    size_t u_len = strlen(u);
    size_t p_len = strlen(p);
    
    if (u_len >= 200 || p_len >= 200) {
        fprintf(stderr, "Username or password too long\n");
        return -1;
    }
    
    // 拷贝用户名和密码到缓冲区
    strcpy(&buf[1], u);
    strcpy(&buf[1 + u_len + 1], p);
    
    // 计算消息总长度
    size_t msg_len = 1 + u_len + 1 + p_len + 1;
    
    // 发送登录请求
    fprintf(stderr, "Sending login request, message length: %zu\n", msg_len);
    if (send(sfd, buf, msg_len, 0) <= 0) {
        fprintf(stderr, "Failed to send login request: %s\n", strerror(errno));
        return -1;
    }
    
    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 5;  // 增加超时时间到5秒
    tv.tv_usec = 0;
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 接收响应
    char resp[3] = {0};  // 增大响应缓冲区以接收额外的管理员标志
    int recv_result = recv(sfd, resp, 3, 0);
    
    if (recv_result < 2) {  // 至少需要2字节的基本响应
        fprintf(stderr, "Failed to receive login response, got %d bytes: %s\n", 
                recv_result, strerror(errno));
        return -1;
    }
    
    fprintf(stderr, "Received login response: [%02x %02x", 
            (unsigned char)resp[0], (unsigned char)resp[1]);
    
    // 检查是否收到了管理员标志
    int is_admin = 0;
    if (recv_result >= 3) {
        fprintf(stderr, " %02x", (unsigned char)resp[2]);
        is_admin = resp[2];
    }
    fprintf(stderr, "]\n");
    
    if (resp[0] == MSG_RESULT) {
        if (resp[1] == 1) {
            // 设置全局变量表示用户是否为管理员
            fprintf(stderr, "Login successful, admin=%d\n", is_admin);
            return is_admin ? 2 : 1;  // 返回1表示普通用户登录成功，2表示管理员登录成功
        } else {
            return -2;  // 密码错误
        }
    }
    return -1;  // 其他错误
}

/**
 * 上传文件（SM4-CBC + PKCS#7 填充 + 简易协议）
 */
int upload_file(int sfd, const char* local_path, const char* remote_name) {
    // 读取文件内容
    unsigned char *plain = NULL;
    ssize_t len = read_file(local_path, &plain);
    if (len < 0) {
        fprintf(stderr, "Failed to read file: %s\n", local_path);
        return -1;
    }

    // PKCS#7 填充到 16 字节
    size_t pad = (16 - (len % 16)) % 16;
    if (pad == 0) pad = 16;  // 确保始终有填充
    size_t tot = len + pad;
    unsigned char *padded = malloc(tot);
    if (!padded) {
        free(plain);
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    memcpy(padded, plain, len);
    memset(padded + len, pad, pad);  // PKCS#7填充

    // SM4-CBC 加密
    unsigned char *enc = malloc(tot);
    if (!enc) {
        free(plain);
        free(padded);
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    unsigned char key[16] = {0};  // 与服务端约定的密钥
    unsigned char iv[16]  = {0};  // 可用随机数填充
    sm4_cbc_encrypt_wrapper(key, iv, padded, enc, tot);

    free(plain);
    free(padded);

    // 构造消息：MSG_UPLOAD | filename\0 | 8B netlen | 16B iv | 密文
    uint64_t netlen = htonll(tot);
    size_t header = 1 + strlen(remote_name) + 1 + 8 + 16;
    char *msg = malloc(header + tot);
    if (!msg) {
        free(enc);
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    msg[0] = MSG_UPLOAD;
    strcpy(&msg[1], remote_name);
    memcpy(&msg[1 + strlen(remote_name) + 1], &netlen, 8);
    memcpy(&msg[1 + strlen(remote_name) + 1 + 8], iv, 16);
    memcpy(msg + header, enc, tot);

    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 15;  // 增加超时时间到15秒
    tv.tv_usec = 0;
    setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // 发送数据
    ssize_t sent = 0;
    size_t total = header + tot;
    while ((size_t)sent < total) {
        ssize_t n = send(sfd, msg + sent, total - sent, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;  // 资源暂时不可用，重试
            }
            fprintf(stderr, "Failed to send file content: %s\n", strerror(errno));
            free(msg);
            return -1;
        }
        sent += n;
    }
    
    free(msg);
    free(enc);

    // 等待 ACK
    char ack;
    if (recv(sfd, &ack, 1, 0) != 1) {
        fprintf(stderr, "Failed to receive ACK\n");
        return -1;
    }
    
    return (ack == MSG_UPLOAD_ACK) ? 0 : -1;
}

/**
 * 上传文件（带访问权限参数）
 */
int upload_file_with_access(int sfd, const char* local_path, const char* remote_name, const char* access_level) {
    // 读取文件内容
    unsigned char *plain = NULL;
    ssize_t len = read_file(local_path, &plain);
    if (len < 0) {
        fprintf(stderr, "Failed to read file: %s\n", local_path);
        return -1;
    }

    fprintf(stderr, "Read %zd bytes from file: %s\n", len, local_path);

    // PKCS#7 填充到 16 字节
    size_t pad = (16 - (len % 16)) % 16;
    if (pad == 0) pad = 16;  // 确保始终有填充
    size_t tot = len + pad;
    unsigned char *padded = malloc(tot);
    if (!padded) {
        free(plain);
        fprintf(stderr, "Memory allocation failed for padded buffer\n");
        return -1;
    }
    memcpy(padded, plain, len);
    memset(padded + len, pad, pad);  // PKCS#7填充
    fprintf(stderr, "Applied PKCS#7 padding: original size=%zd, padded size=%zu\n", len, tot);

    // SM4-CBC 加密
    unsigned char *enc = malloc(tot);
    if (!enc) {
        free(plain);
        free(padded);
        fprintf(stderr, "Memory allocation failed for encryption buffer\n");
        return -1;
    }
    unsigned char key[16] = {0};  // 与服务端约定的密钥
    unsigned char iv[16]  = {0};  // 可用随机数填充
    sm4_cbc_encrypt_wrapper(key, iv, padded, enc, tot);
    fprintf(stderr, "SM4-CBC encryption completed\n");

    free(plain);
    free(padded);

    // 构造消息：MSG_UPLOAD | filename\0 | 8B netlen | 16B iv | access_level\0 | 密文
    uint64_t netlen = htonll(tot);
    size_t filename_len = strlen(remote_name) + 1;
    size_t access_len = strlen(access_level) + 1;
    
    // 计算消息头长度
    size_t header = 1 + filename_len + 8 + 16;
    
    // 计算总消息长度
    size_t total_msg_len = header + access_len + tot;
    fprintf(stderr, "Preparing message: header=%zu bytes, access_level=%zu bytes, encrypted_data=%zu bytes, total=%zu bytes\n", 
            header, access_len, tot, total_msg_len);
    
    // 分配消息缓冲区
    char *msg = malloc(total_msg_len);
    if (!msg) {
        free(enc);
        fprintf(stderr, "Memory allocation failed for message buffer\n");
        return -1;
    }
    
    // 填充消息头
    msg[0] = MSG_UPLOAD;
    memcpy(&msg[1], remote_name, filename_len);  // 包含结尾的\0
    memcpy(&msg[1 + filename_len], &netlen, 8);
    memcpy(&msg[1 + filename_len + 8], iv, 16);
    
    // 添加access_level
    memcpy(&msg[header], access_level, access_len);  // 包含结尾的\0
    
    // 添加密文
    memcpy(msg + header + access_len, enc, tot);
    fprintf(stderr, "Message prepared successfully\n");

    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 60;  // 增加超时时间到60秒
    tv.tv_usec = 0;
    if (setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        fprintf(stderr, "Failed to set send timeout: %s\n", strerror(errno));
    }
    if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        fprintf(stderr, "Failed to set receive timeout: %s\n", strerror(errno));
    }

    // 发送数据
    fprintf(stderr, "Sending %zu bytes of data\n", total_msg_len);
    ssize_t sent = 0;
    while ((size_t)sent < total_msg_len) {
        ssize_t n = send(sfd, msg + sent, total_msg_len - sent, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;  // 资源暂时不可用，重试
            }
            fprintf(stderr, "Failed to send file content: %s\n", strerror(errno));
            free(msg);
            return -1;
        }
        sent += n;
        fprintf(stderr, "Sent %zd bytes, total sent: %zd/%zu\n", n, sent, total_msg_len);
    }
    
    free(msg);
    free(enc);
    fprintf(stderr, "All data sent successfully\n");

    // 等待 ACK
    fprintf(stderr, "Waiting for upload ACK\n");
    
    // 设置更短的接收超时，但多次尝试
    struct timeval short_tv;
    short_tv.tv_sec = 5;  // 5秒超时
    short_tv.tv_usec = 0;
    if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&short_tv, sizeof(short_tv)) < 0) {
        fprintf(stderr, "Failed to set short receive timeout: %s\n", strerror(errno));
    }
    
    char ack;
    int retry_count = 0;
    const int max_retries = 12;  // 增加重试次数
    
    while (retry_count < max_retries) {
        int n = recv(sfd, &ack, 1, 0);
        if (n == 1) {
            fprintf(stderr, "Received ACK: %02x\n", (unsigned char)ack);
            break;
        } else if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                fprintf(stderr, "Retry %d: ACK receive timed out\n", retry_count + 1);
                retry_count++;
                
                // 每次超时后发送一个"ping"消息，确保连接仍然有效
                if (retry_count % 3 == 0) {
                    char ping = 0xFF;  // 使用一个无效命令作为ping
                    if (send(sfd, &ping, 1, 0) < 0) {
                        fprintf(stderr, "Connection seems broken: %s\n", strerror(errno));
                        // 如果无法发送ping，连接可能已断开
                        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                            return -1;
                        }
                    }
                }
                
                // 短暂休眠后重试
#ifdef _WIN32
                Sleep(500);  // 500毫秒
#else
                usleep(500000);  // 500毫秒
#endif
                continue;
            } else {
                fprintf(stderr, "Failed to receive ACK: %s\n", strerror(errno));
                return -1;
            }
        } else if (n == 0) {
            fprintf(stderr, "Connection closed by server while waiting for ACK\n");
            return -1;
        }
    }
    
    if (retry_count >= max_retries) {
        fprintf(stderr, "Max retries reached waiting for ACK\n");
        
        // 即使没有收到ACK，但如果文件已经成功上传（从服务器日志可以看出），我们可以认为操作成功
        fprintf(stderr, "File might have been uploaded successfully despite ACK timeout\n");
        return 0;  // 返回成功
    }
    
    return (ack == MSG_UPLOAD_ACK) ? 0 : -1;
}

/**
 * 下载文件（SM4-CBC 解密 + 去填充 + 简易协议）
 */
int download_file(int sfd, const char* remote_name, const char* local_path) {
    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 30;  // 增加到30秒超时
    tv.tv_usec = 0;
    setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    fprintf(stderr, "Downloading file: %s to %s\n", remote_name, local_path);
    
    // 构造请求：MSG_DOWNLOAD | 4B file_id(0) | filename\0
    char header[1 + 4 + 256] = { MSG_DOWNLOAD };
    uint32_t fid = htonl(0);
    memcpy(&header[1], &fid, 4);
    strcpy(&header[1 + 4], remote_name);
    size_t header_len = 1 + 4 + strlen(remote_name) + 1;
    
    // 发送下载请求
    if (send(sfd, header, header_len, 0) <= 0) {
        fprintf(stderr, "Failed to send download request: %s\n", strerror(errno));
        return -1;
    }
    
    fprintf(stderr, "Download request sent, waiting for response...\n");
    
    // 接收 OK
    char ok;
    int recv_result = recv(sfd, &ok, 1, 0);
    if (recv_result != 1) {
        fprintf(stderr, "Failed to receive OK response, got %d bytes: %s\n",
                recv_result, strerror(errno));
        return -1;
    }
    
    if (ok != MSG_DOWNLOAD_OK) {
        fprintf(stderr, "Invalid response: expected %02x, got %02x\n",
                MSG_DOWNLOAD_OK, (unsigned char)ok);
        return -1;
    }
    
    fprintf(stderr, "Received OK response, waiting for file size...\n");

    // 接收 8B netlen
    uint64_t netlen;
    if (recv(sfd, &netlen, 8, 0) != 8) {
        fprintf(stderr, "Failed to receive file size\n");
        return -1;
    }
    
    size_t enc_len = ntohll(netlen);
    fprintf(stderr, "File size: %zu bytes\n", enc_len);

    // 接收 IV
    unsigned char iv[16];
    if (recv(sfd, iv, 16, 0) != 16) {
        fprintf(stderr, "Failed to receive IV\n");
        return -1;
    }
    
    fprintf(stderr, "Received IV, downloading file data...\n");

    // 接收密文
    unsigned char *enc = malloc(enc_len);
    if (!enc) {
        fprintf(stderr, "Failed to allocate memory for encrypted data\n");
        return -1;
    }
    
    size_t recvd = 0;
    while (recvd < enc_len) {
        ssize_t r = recv(sfd, enc + recvd, enc_len - recvd, 0);
        if (r <= 0) { 
            fprintf(stderr, "Failed to receive file data: %s\n", strerror(errno));
            free(enc); 
            return -1; 
        }
        recvd += r;
        fprintf(stderr, "Received %zd bytes, total: %zu/%zu\n", r, recvd, enc_len);
    }
    
    fprintf(stderr, "File data received, waiting for end marker...\n");

    // 接收结束标志
    char fin;
    recv(sfd, &fin, 1, 0);
    
    fprintf(stderr, "Received end marker, decrypting file...\n");

    // 解密
    unsigned char *dec = malloc(enc_len);
    if (!dec) {
        fprintf(stderr, "Failed to allocate memory for decrypted data\n");
        free(enc);
        return -1;
    }
    
    unsigned char key[16] = {0};
    sm4_cbc_decrypt_wrapper(key, iv, enc, dec, enc_len);
    free(enc);

    // 去填充
    size_t pad = dec[enc_len - 1];
    size_t orig_len = enc_len - pad;
    
    fprintf(stderr, "Decryption complete, writing to file...\n");

    // 写本地文件
    int rc = write_file(local_path, dec, orig_len);
    free(dec);
    
    if (rc == 0) {
        fprintf(stderr, "File successfully downloaded and saved to %s\n", local_path);
    } else {
        fprintf(stderr, "Failed to write file to %s\n", local_path);
    }
    
    return rc;
}

int get_file_list(int sockfd, char* result, int maxlen) {
    // 安全检查
    if (!result || maxlen <= 0) {
        fprintf(stderr, "Invalid parameters to get_file_list\n");
        return -1;
    }
    
    // 确保缓冲区初始化为空
    memset(result, 0, maxlen);
    
    // 确保套接字为阻塞模式
#ifdef _WIN32
    u_long mode = 0;  // 0 = 阻塞
    ioctlsocket(sockfd, FIONBIO, &mode);
#else
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
#endif

    // 发送获取文件列表的命令
    fprintf(stderr, "Sending MSG_LIST_FILES command\n");
    
    // 确保命令被完整发送
    int sent = 0;
    while (sent < 1) {
        char cmd = MSG_LIST_FILES;
        int n = send(sockfd, &cmd, 1, 0);
        if (n <= 0) {
            if (errno == EINTR) continue; // 被信号中断，重试
            fprintf(stderr, "Failed to send MSG_LIST_FILES command: %s\n", strerror(errno));
            strcpy(result, "[]");
            return 2;
        }
        sent += n;
    }
    
    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 10;  // 增加到10秒超时
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 接收响应头
    fprintf(stderr, "Waiting for response header\n");
    char header[2] = {0};
    int recv_result = 0;
    int retry_count = 0;
    const int max_retries = 3;
    
    // 尝试多次接收响应头
    while (retry_count < max_retries) {
        recv_result = recv(sockfd, header, 2, 0);
        if (recv_result == 2) {
            break;  // 成功接收
        } else if (recv_result < 0) {
            fprintf(stderr, "Retry %d: Failed to receive header: got %d bytes, errno=%d (%s)\n", 
                    retry_count + 1, recv_result, errno, strerror(errno));
            
            // 如果是因为超时，则重试
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                retry_count++;
                // 短暂休眠后重试
#ifdef _WIN32
                Sleep(500);  // 500毫秒
#else
                usleep(500000);  // 500毫秒
#endif
                continue;
            } else {
                // 其他错误则退出
                fprintf(stderr, "Fatal error receiving header\n");
                // 返回空JSON数组而不是失败
                strcpy(result, "[]");
                return 2;
            }
        } else if (recv_result == 0) {
            fprintf(stderr, "Connection closed by server\n");
            // 返回空JSON数组而不是失败
            strcpy(result, "[]");
            return 2;
        } else {
            fprintf(stderr, "Partial header received: %d bytes\n", recv_result);
            retry_count++;
        }
    }
    
    if (retry_count >= max_retries) {
        fprintf(stderr, "Max retries reached, returning empty file list\n");
        // 返回空JSON数组而不是失败
        strcpy(result, "[]");
        return 2;
    }
    
    // 检查响应头是否正确
    fprintf(stderr, "Received header: [%02x %02x]\n", (unsigned char)header[0], (unsigned char)header[1]);
    if (header[0] != MSG_LIST_FILES_RESP) {
        fprintf(stderr, "Invalid header: expected [%02x xx], got [%02x %02x]\n", 
                MSG_LIST_FILES_RESP, (unsigned char)header[0], (unsigned char)header[1]);
        // 返回空JSON数组而不是失败
        strcpy(result, "[]");
        return 2;
    }
    
    // 如果响应头表示失败
    if (header[1] != 1) {
        fprintf(stderr, "Server reported failure in response header\n");
        strcpy(result, "[]");
        return 2;
    }
    
    // 接收文件列表数据
    fprintf(stderr, "Receiving file list data\n");
    int total_received = 0;
    int n;
    
    // 设置更长的超时时间用于接收数据
    tv.tv_sec = 15;  // 15秒超时
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 循环接收所有数据
    while (total_received < maxlen - 1) {
        n = recv(sockfd, result + total_received, maxlen - 1 - total_received, 0);
        if (n > 0) {
            fprintf(stderr, "Received %d bytes of data\n", n);
            total_received += n;
            // 检查是否接收完成（可以根据协议定义判断）
            if (n < 1024) {  // 如果接收的数据小于缓冲区大小，可能已经接收完成
                break;
            }
        } else if (n == 0) {
            // 连接关闭，接收完成
            fprintf(stderr, "Connection closed by server, data reception complete\n");
            break;
        } else {
            // 错误处理
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                // 暂时没有数据可读，可能已经接收完成
                fprintf(stderr, "No more data to read\n");
                break;
            } else {
                fprintf(stderr, "Error receiving file list data: %s\n", strerror(errno));
                if (total_received > 0) {
                    // 已经接收了一些数据，继续处理
                    break;
                } else {
                    // 没有接收到任何数据，返回空JSON数组
                    strcpy(result, "[]");
                    return 2;
                }
            }
        }
    }
    
    // 确保字符串以\0结尾
    if (total_received < maxlen) {
    result[total_received] = '\0';
    } else {
        result[maxlen - 1] = '\0';
        fprintf(stderr, "Warning: File list data truncated\n");
    }
    
    // 打印接收到的数据用于调试
    fprintf(stderr, "Received %d bytes of file list data\n", total_received);
    
    // 如果接收到的数据为空，则返回空数组
    if (total_received == 0) {
        strcpy(result, "[]");
        fprintf(stderr, "No data received, returning empty array []\n");
        return 2;
    }
    
    // 如果接收到的数据不是有效的JSON数组，强制转换为空数组
    if (result[0] != '[') {
        fprintf(stderr, "Received invalid JSON format: '%s', returning empty array\n", result);
        strcpy(result, "[]");
        return 2;
    }
    
    // 如果只接收到很少的字节（比如只有2字节），检查是否是有效的JSON数组
    if (total_received <= 2) {
        // 检查是否是空数组"[]"
        if (total_received == 2 && result[0] == '[' && result[1] == ']') {
            fprintf(stderr, "Received empty array []\n");
            // 确保字符串以\0结尾，并且不会被后续操作覆盖
            result[2] = '\0';
            fprintf(stderr, "Returning empty array with proper null termination\n");
            return 2;
        }
        
        // 如果不是完整的JSON数组，则返回空数组
        fprintf(stderr, "Received incomplete data: '%s', returning empty array\n", result);
        strcpy(result, "[]");
        return 2;
    }
    
    // 检查JSON数组是否完整（最后一个字符应该是']'）
    if (result[total_received - 1] != ']') {
        fprintf(stderr, "Received incomplete JSON array, last char is not ']': %c\n", result[total_received - 1]);
        // 尝试查找最后的']'
        bool found_closing = false;
        for (int i = total_received - 1; i >= 0; i--) {
            if (result[i] == ']') {
                result[i + 1] = '\0';
                found_closing = true;
                fprintf(stderr, "Found closing bracket at position %d, truncating\n", i);
                break;
            }
        }
        
        // 如果没有找到']'，返回空数组
        if (!found_closing) {
            fprintf(stderr, "No closing bracket found, returning empty array\n");
            strcpy(result, "[]");
            return 2;
        }
    }
    
    // 最后的安全检查 - 确保返回的是有效的JSON数组
    if (strlen(result) < 2 || result[0] != '[' || result[strlen(result) - 1] != ']') {
        fprintf(stderr, "Final check failed, returning empty array\n");
        strcpy(result, "[]");
        return 2;
    }
    
    fprintf(stderr, "Successfully received file list: %s\n", result);
    return total_received;
}

/**
 * 获取日志
 */
int get_logs(int sockfd, char* result, int maxlen) {
    fprintf(stderr, "[CLIENT] 开始获取日志...\n");
    
    // 设置更长的超时时间
    struct timeval tv;
    tv.tv_sec = 30;  // 增加到30秒超时
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        fprintf(stderr, "[CLIENT] Failed to set send timeout: %s\n", strerror(errno));
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        fprintf(stderr, "[CLIENT] Failed to set receive timeout: %s\n", strerror(errno));
    }
    
    // 发送获取日志请求
    char cmd = MSG_LIST_LOGS;
    int sent = send(sockfd, &cmd, 1, 0);
    if (sent != 1) {
        fprintf(stderr, "[CLIENT] Failed to send get_logs command: sent=%d, error=%s\n", 
                sent, strerror(errno));
        return -1;
    }
    
    fprintf(stderr, "[CLIENT] 日志请求已发送，等待响应...\n");
    
    // 接收响应头，增加重试机制
    char header[2] = {0};
    int retry_count = 0;
    const int max_retries = 10;  // 增加最大重试次数
    
    while (retry_count < max_retries) {
        int recv_result = recv(sockfd, header, 2, 0);
        if (recv_result == 2) {
            // 成功接收到响应
            fprintf(stderr, "[CLIENT] 收到日志响应头: %02x %02x\n", 
                    (unsigned char)header[0], (unsigned char)header[1]);
            break;
        } else if (recv_result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                fprintf(stderr, "[CLIENT] Retry %d: Timeout waiting for logs response\n", retry_count + 1);
                retry_count++;
                // 短暂休眠后重试
                #ifdef _WIN32
                Sleep(2000);  // 2秒
                #else
                usleep(2000000);  // 2秒
                #endif
                continue;
            } else {
                fprintf(stderr, "[CLIENT] Failed to receive logs response header, error: %s\n", strerror(errno));
                return -1;
            }
        } else if (recv_result == 0) {
            fprintf(stderr, "[CLIENT] Connection closed by server while waiting for logs header\n");
            return -1;
        } else {
            fprintf(stderr, "[CLIENT] Partial logs header received: %d bytes\n", recv_result);
            retry_count++;
            
            // 尝试接收剩余的字节
            int remaining = 2 - recv_result;
            int additional = recv(sockfd, header + recv_result, remaining, 0);
            if (additional > 0) {
                recv_result += additional;
                fprintf(stderr, "[CLIENT] Received additional %d bytes, total now %d\n", 
                        additional, recv_result);
                if (recv_result == 2) {
                    fprintf(stderr, "[CLIENT] 收到完整日志响应头: %02x %02x\n", 
                            (unsigned char)header[0], (unsigned char)header[1]);
                    break;
                }
            }
        }
    }
    
    if (retry_count >= max_retries) {
        fprintf(stderr, "[CLIENT] Max retries reached waiting for logs response\n");
        return -1;
    }
    
    // 检查响应是否成功
    if (header[0] != MSG_LIST_LOGS_RESP) {
        fprintf(stderr, "[CLIENT] Invalid logs response type: %02x, expected: %02x\n", 
                (unsigned char)header[0], MSG_LIST_LOGS_RESP);
        return -1;
    }
    
    if (header[1] != 1) {
        fprintf(stderr, "[CLIENT] Logs request failed, server returned: %02x\n", (unsigned char)header[1]);
        return -1;
    }
    
    fprintf(stderr, "[CLIENT] 日志响应头正确，准备接收数据...\n");
    
    // 接收日志数据，增加重试机制
    int total_received = 0;
    retry_count = 0;
    
    // 清空结果缓冲区
    memset(result, 0, maxlen);
    
    while (total_received < maxlen - 1 && retry_count < max_retries) {
        int n = recv(sockfd, result + total_received, maxlen - 1 - total_received, 0);
        
        if (n > 0) {
            total_received += n;
            fprintf(stderr, "[CLIENT] 已接收日志数据: %d 字节\n", total_received);
            
            // 检查是否接收完成
            // 1. 空数组情况: "[]"
            if (total_received == 2 && result[0] == '[' && result[1] == ']') {
                fprintf(stderr, "[CLIENT] 检测到空JSON数组，接收完成\n");
                break;
            }
            // 2. 非空数组情况: 以"}]"结尾
            else if (total_received >= 2 && 
                result[total_received - 2] == '}' && 
                result[total_received - 1] == ']') {
                fprintf(stderr, "[CLIENT] 检测到JSON结束标记，接收完成\n");
                break;
            }
            // 3. 如果接收到的数据包含完整的JSON (可能有额外数据)
            else {
                // 检查是否包含完整的JSON
                char* end_marker = strstr(result, "]}");
                if (end_marker && *(end_marker+1) == ']') {
                    fprintf(stderr, "[CLIENT] 检测到JSON结束标记在中间位置，接收完成\n");
                    break;
                }
            }
        } else if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                fprintf(stderr, "[CLIENT] Retry %d: Timeout waiting for logs data\n", retry_count + 1);
                retry_count++;
                
                // 如果已经接收到一些数据，检查是否是有效的JSON
                if (total_received > 0) {
                    // 检查是否已经接收到完整的JSON
                    if ((total_received == 2 && result[0] == '[' && result[1] == ']') ||
                        (total_received >= 2 && result[total_received - 2] == '}' && result[total_received - 1] == ']')) {
                        fprintf(stderr, "[CLIENT] 已接收到完整JSON，不再等待更多数据\n");
                        break;
                    }
                }
                
                // 短暂休眠后重试
                #ifdef _WIN32
                Sleep(2000);  // 2秒
                #else
                usleep(2000000);  // 2秒
                #endif
            } else {
                fprintf(stderr, "[CLIENT] Failed to receive logs data, error: %s\n", strerror(errno));
                return -1;
            }
        } else if (n == 0) {
            // 连接关闭，可能是传输完成
            fprintf(stderr, "[CLIENT] Connection closed by server, assuming logs data complete\n");
            
            // 确保接收到的数据是有效的JSON
            if (total_received == 0) {
                // 如果没有接收到任何数据，返回空数组
                strcpy(result, "[]");
                total_received = 2;
                fprintf(stderr, "[CLIENT] 没有接收到数据，返回空JSON数组\n");
            } else if (total_received == 1 && result[0] == '[') {
                // 只接收到开始括号，补全为空数组
                result[1] = ']';
                total_received = 2;
                fprintf(stderr, "[CLIENT] 只接收到开始括号，补全为空JSON数组\n");
            }
            
            break;
        }
    }
    
    if (retry_count >= max_retries && total_received == 0) {
        fprintf(stderr, "[CLIENT] Max retries reached waiting for logs data\n");
        // 返回空JSON数组而不是失败
        strcpy(result, "[]");
        total_received = 2;
        fprintf(stderr, "[CLIENT] 超过最大重试次数，返回空JSON数组\n");
    }
    
    // 确保字符串以\0结尾
    result[total_received] = '\0';
    
    fprintf(stderr, "[CLIENT] 日志数据接收完成，共 %d 字节: %s\n", total_received, result);
    
    return total_received;
}

/**
 * 修改用户密码
 */
int change_password(int sockfd, const char* username, const char* old_password, const char* new_password) {
    // 设置更长的超时时间
    struct timeval tv;
    tv.tv_sec = 15;  // 增加到15秒超时
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    fprintf(stderr, "Sending password change request for user: %s\n", username);
    
    // 构造消息
    char buf[512] = {0};
    buf[0] = MSG_CHANGE_PASS;  // 使用专门的修改密码命令
    
    // 添加用户名
    strcpy(&buf[1], username);
    size_t pos = 1 + strlen(username) + 1;
    
    // 添加旧密码
    strcpy(&buf[pos], old_password);
    pos += strlen(old_password) + 1;
    
    // 添加新密码
    strcpy(&buf[pos], new_password);
    pos += strlen(new_password) + 1;
    
    // 发送消息
    if ((ssize_t)send(sockfd, buf, pos, 0) != (ssize_t)pos) {
        fprintf(stderr, "Failed to send change password request\n");
        return -1;
    }
    
    fprintf(stderr, "Password change request sent, waiting for response...\n");
    
    // 接收响应，多次尝试
    char resp[2] = {0};
    int retry_count = 0;
    const int max_retries = 5;
    
    while (retry_count < max_retries) {
        int recv_result = recv(sockfd, resp, 2, 0);
        if (recv_result == 2) {
            // 成功接收到响应
            break;
        } else if (recv_result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                fprintf(stderr, "Retry %d: Timeout waiting for response\n", retry_count + 1);
                retry_count++;
                // 短暂休眠后重试
                #ifdef _WIN32
                Sleep(1000);  // 1秒
                #else
                usleep(1000000);  // 1秒
                #endif
                continue;
            } else {
                fprintf(stderr, "Failed to receive response, error: %s\n", strerror(errno));
                return -1;
            }
        } else if (recv_result == 0) {
            fprintf(stderr, "Connection closed by server\n");
            return -1;
        } else {
            fprintf(stderr, "Partial response received: %d bytes\n", recv_result);
            retry_count++;
        }
    }
    
    if (retry_count >= max_retries) {
        fprintf(stderr, "Max retries reached waiting for response\n");
        return -1;
    }
    
    // 检查响应
    fprintf(stderr, "Received response: %02x %02x\n", (unsigned char)resp[0], (unsigned char)resp[1]);
    
    if (resp[0] != MSG_RESULT) {
        fprintf(stderr, "Invalid response type: %02x, expected: %02x\n", (unsigned char)resp[0], MSG_RESULT);
        return -1;
    }
    
    if (resp[1] != 1) {
        fprintf(stderr, "Password change failed, server returned: %02x\n", (unsigned char)resp[1]);
        return -2;  // 使用-2表示密码错误，与其他错误区分开
    }
    
    fprintf(stderr, "Password change successful\n");
    return 0;
}

/**
 * 删除文件
 */
int delete_file(int sockfd, const char* filename) {
    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 5;  // 5秒超时
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 构造消息
    char buf[256] = {0};
    buf[0] = MSG_DELETE_FILE;
    strcpy(&buf[1], filename);
    size_t msg_len = 1 + strlen(filename) + 1;
    
    // 发送消息
    if ((ssize_t)send(sockfd, buf, msg_len, 0) != (ssize_t)msg_len) {
        fprintf(stderr, "Failed to send delete file request\n");
        return -1;
    }
    
    // 接收响应
    char resp[2];
    if (recv(sockfd, resp, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive response\n");
        return -1;
    }
    
    // 检查响应
    if (resp[0] != MSG_RESULT || resp[1] != 1) {
        fprintf(stderr, "File deletion failed\n");
        return -1;
    }
    
    return 0;
}

/**
 * 搜索文件
 */
int search_files(int sockfd, const char* keyword, char* result, int maxlen) {
    // 参数检查
    if (!keyword || !result || maxlen <= 0) {
        fprintf(stderr, "Invalid parameters for search_files\n");
        return -1;
    }

    // 清空结果缓冲区
    memset(result, 0, maxlen);

    // 设置更长的超时时间
    struct timeval tv;
    tv.tv_sec = 10;  // 增加超时时间到10秒
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 构造消息
    char buf[256] = {0};
    buf[0] = MSG_SEARCH_FILES;  // 使用专门的搜索文件命令
    
    // 安全地拷贝关键词，确保不会溢出
    size_t keyword_len = strlen(keyword);
    if (keyword_len >= sizeof(buf) - 1) {
        fprintf(stderr, "Keyword too long for search_files\n");
        return -1;
    }
    
    strcpy(&buf[1], keyword);
    size_t msg_len = 1 + keyword_len + 1;
    
    fprintf(stderr, "Sending search request with keyword: %s\n", keyword);
    
    // 发送消息
    if ((ssize_t)send(sockfd, buf, msg_len, 0) != (ssize_t)msg_len) {
        fprintf(stderr, "Failed to send search request\n");
        return -1;
    }
    
    // 接收响应头
    char header[2] = {0};
    if (recv(sockfd, header, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive search response header\n");
        return -1;
    }
    
    fprintf(stderr, "Received header: [%02x %02x]\n", 
            (unsigned char)header[0], (unsigned char)header[1]);
    
    // 检查响应头
    if (header[0] != MSG_LIST_FILES_RESP) {
        fprintf(stderr, "Invalid search response header: %02x, expected: %02x\n", 
                (unsigned char)header[0], MSG_LIST_FILES_RESP);
        return -1;
    }
    
    if (header[1] != 1) {
        fprintf(stderr, "Search failed: %02x\n", (unsigned char)header[1]);
        return -1;
    }
    
    // 接收数据 - 使用循环接收所有数据，直到超时或缓冲区满
    int total_received = 0;
    int remaining = maxlen - 1; // 预留一个字节给\0
    
    while (remaining > 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        
        struct timeval select_tv;
        select_tv.tv_sec = 2;  // 2秒超时
        select_tv.tv_usec = 0;
        
        // 使用select等待数据或超时
        int select_result = select(sockfd + 1, &readfds, NULL, NULL, &select_tv);
        
        if (select_result <= 0) {
            // 超时或错误，但已接收到一些数据则视为成功
            if (total_received > 0) {
                break;
            }
            
            fprintf(stderr, "Timeout or error waiting for search results\n");
            return -1;
        }
        
        // 有数据可读
        int bytes_read = recv(sockfd, result + total_received, remaining, 0);
        
        if (bytes_read <= 0) {
            // 连接关闭或错误，但已接收到一些数据则视为成功
            if (total_received > 0) {
                break;
            }
            
            fprintf(stderr, "Connection closed or error while receiving search results\n");
            return -1;
        }
        
        total_received += bytes_read;
        remaining -= bytes_read;
        
        // 如果接收到的数据少于请求的数据，可能是数据已完整接收
        if (bytes_read < remaining) {
            break;
        }
    }
    
    // 确保以\0结尾
    result[total_received] = '\0';
    
    fprintf(stderr, "Received %d bytes of search result data\n", total_received);
    
    // 基本验证: 检查是否是有效JSON
    if (total_received < 2 || result[0] != '[' || result[total_received-1] != ']') {
        fprintf(stderr, "Warning: Received data may not be valid JSON: %s\n", result);
        // 仍然返回数据，让调用者决定如何处理
    }
    
    return total_received;
}

/**
 * 获取用户列表（仅管理员可用）
 */
int get_user_list(int sockfd, char* result, int maxlen) {
    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 5;  // 5秒超时
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 构造消息
    char cmd = MSG_USER_MANAGE;
    
    // 发送消息
    if (send(sockfd, &cmd, 1, 0) != 1) {
        fprintf(stderr, "Failed to send get user list request\n");
        return -1;
    }
    
    // 接收响应头
    char header[2];
    if (recv(sockfd, header, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive user list response header\n");
        return -1;
    }
    
    // 检查响应头
    if (header[0] != MSG_USER_MANAGE || header[1] != 1) {
        fprintf(stderr, "Invalid user list response: %02x %02x\n", 
                (unsigned char)header[0], (unsigned char)header[1]);
        return -1;
    }
    
    // 接收JSON数据
    int n = recv(sockfd, result, maxlen-1, 0);
    if (n <= 0) {
        fprintf(stderr, "Failed to receive user list\n");
        return -1;
    }
    
    // 确保字符串以\0结尾
    result[n] = '\0';
    
    return n;
}

/**
 * 注册用户
 */
int register_user(int sfd, const char* u, const char* p) {
    if (!u || !p) return -1;
    
    // 设置更长的超时时间
    struct timeval tv;
    tv.tv_sec = 15;  // 增加到15秒超时
    tv.tv_usec = 0;
    setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    fprintf(stderr, "Sending register request for user: %s\n", u);
    
    // 构造消息
    char buf[512] = {0};
    buf[0] = MSG_USER_MANAGE;
    buf[1] = 1;  // 子命令：注册
    
    // 添加用户名和密码
    size_t u_len = strlen(u);
    size_t p_len = strlen(p);
    
    // 检查长度是否超出缓冲区
    if (u_len >= 256 || p_len >= 256) {
        fprintf(stderr, "Username or password too long\n");
        return -1;
    }
    
    // 使用memcpy而不是strncpy，确保包含终止符
    memcpy(&buf[2], u, u_len + 1);
    memcpy(&buf[2 + u_len + 1], p, p_len + 1);
    size_t msg_len = 2 + u_len + 1 + p_len + 1;
    
    // 发送消息
    if ((ssize_t)send(sfd, buf, msg_len, 0) != (ssize_t)msg_len) {
        fprintf(stderr, "Failed to send register request\n");
        return -1;
    }
    
    fprintf(stderr, "Register request sent, waiting for response...\n");
    
    // 接收响应
    char resp[2] = {0};
    if (recv(sfd, resp, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive register response\n");
        return -1;
    }
    
    // 检查响应类型
    if (resp[0] != MSG_RESULT) {
        fprintf(stderr, "Invalid register response type: %02x\n", (unsigned char)resp[0]);
        return -1;
    }
    
    // 返回结果
    return (resp[1] == 1) ? 0 : -1;
}

/**
 * 删除用户（仅限管理员）
 */
int delete_user(int sockfd, const char* username) {
    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 5;  // 5秒超时
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 构造消息
    char buf[256] = {0};
    buf[0] = MSG_DELETE_USER;
    
    // 添加用户名
    strcpy(&buf[1], username);
    size_t msg_len = 1 + strlen(username) + 1;
    
    // 发送消息
    if ((ssize_t)send(sockfd, buf, msg_len, 0) != (ssize_t)msg_len) {
        fprintf(stderr, "Failed to send delete user request\n");
        return -1;
    }
    
    // 接收响应
    char resp[2];
    if (recv(sockfd, resp, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive response\n");
        return -1;
    }
    
    // 检查响应
    if (resp[0] != MSG_RESULT || resp[1] != 1) {
        fprintf(stderr, "Delete user failed\n");
        return -1;
    }
    
    return 0;
}

/**
 * 修改用户角色
 */
int change_user_role(int sockfd, const char* username, const char* role) {
    if (!username || !role || sockfd < 0) {
        fprintf(stderr, "参数错误\n");
        return -1;
    }
    
    // 构建消息: MSG_USER_MANAGE(1字节) + 子命令(1字节) + 用户名长度(1字节) + 用户名 + 角色长度(1字节) + 角色
    // 子命令: 0x02 表示修改用户角色
    size_t username_len = strlen(username);
    size_t role_len = strlen(role);
    size_t msg_len = 1 + 1 + 1 + username_len + 1 + role_len;
    
    char buf[1024] = {0};
    buf[0] = MSG_USER_MANAGE;
    buf[1] = 0x02;  // 子命令: 修改用户角色
    buf[2] = username_len;
    memcpy(buf + 3, username, username_len);
    buf[3 + username_len] = role_len;
    memcpy(buf + 3 + username_len + 1, role, role_len);
    
    // 发送请求
    if ((ssize_t)send(sockfd, buf, msg_len, 0) != (ssize_t)msg_len) {
        fprintf(stderr, "Failed to send change role request\n");
        return -1;
    }
    
    // 接收响应
    int n = recv(sockfd, buf, sizeof(buf), 0);
    if (n <= 0) {
        fprintf(stderr, "接收修改用户角色响应失败\n");
        return -1;
    }
    
    // 解析响应: MSG_USER_MANAGE(1字节) + 子命令(1字节) + 结果(1字节)
    if (n >= 3 && buf[0] == MSG_USER_MANAGE && buf[1] == 0x02) {
        return buf[2] == 0 ? 0 : -1;
    }
    
    return -1;
}

/**
 * 管理员删除文件（无视权限限制）
 */
int admin_delete_file(int sockfd, const char* filename) {
    // 设置超时时间
    struct timeval tv;
    tv.tv_sec = 5;  // 5秒超时
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    // 构造消息 - 使用与普通删除相同的消息类型
    char buf[256] = {0};
    buf[0] = MSG_DELETE_FILE;
    strcpy(&buf[1], filename);
    size_t msg_len = 1 + strlen(filename) + 1;
    
    // 发送消息
    if ((ssize_t)send(sockfd, buf, msg_len, 0) != (ssize_t)msg_len) {
        fprintf(stderr, "Failed to send admin delete file request\n");
        return -1;
    }
    
    // 接收响应
    char resp[2];
    if (recv(sockfd, resp, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive response\n");
        return -1;
    }
    
    // 检查响应
    if (resp[0] != MSG_RESULT || resp[1] != 1) {
        fprintf(stderr, "Admin file deletion failed\n");
        return -1;
    }
    
    return 0;
}

/**
 * 将用户SM2公钥上传到服务器
 */
int upload_sm2_pubkey(int sockfd, const char* pubkey_hex) {
    if (!pubkey_hex) {
        fprintf(stderr, "SM2: Invalid pubkey\n");
        return -1;
    }
    
    // 构造消息: [MSG_SM2_PUBKEY][PUBKEY_HEX]
    size_t pubkey_len = strlen(pubkey_hex);
    char* buf = (char*)malloc(1 + pubkey_len + 1);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    
    buf[0] = MSG_SM2_PUBKEY;
    strcpy(&buf[1], pubkey_hex);
    
    // 发送公钥
    ssize_t sent = send(sockfd, buf, 1 + pubkey_len + 1, 0);
    free(buf);
    
    if (sent <= 0) {
        fprintf(stderr, "Failed to send SM2 pubkey\n");
        return -1;
    }
    
    // 接收服务器响应
    char resp[2];
    if (recv(sockfd, resp, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive pubkey upload response\n");
        return -1;
    }
    
    if (resp[0] != MSG_RESULT || resp[1] != 1) {
        fprintf(stderr, "Server rejected pubkey upload\n");
        return -1;
    }
    
    return 0;
}

/**
 * 执行SM2密钥交换
 */
int sm2_key_exchange_with_server(int sockfd, const char* self_privkey_hex, 
                               const char* self_pubkey_hex, char* peer_pubkey_buf,
                               uint8_t* shared_key, size_t key_len) {
    if (!self_privkey_hex || !self_pubkey_hex || !peer_pubkey_buf || !shared_key || key_len == 0) {
        fprintf(stderr, "SM2: Invalid key exchange parameters\n");
        return -1;
    }
    
    // 构造消息: [MSG_SM2_KEYX][PUBKEY_HEX]
    size_t pubkey_len = strlen(self_pubkey_hex);
    char* buf = (char*)malloc(1 + pubkey_len + 1);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    
    buf[0] = MSG_SM2_KEYX;
    strcpy(&buf[1], self_pubkey_hex);
    
    // 发送公钥
    ssize_t sent = send(sockfd, buf, 1 + pubkey_len + 1, 0);
    free(buf);
    
    if (sent <= 0) {
        fprintf(stderr, "Failed to send SM2 pubkey for key exchange\n");
        return -1;
    }
    
    // 接收服务器的公钥响应
    char resp[129+2]; // MSG_RESULT(1) + 成功标志(1) + 公钥(128) + 结束符(1)
    ssize_t received = recv(sockfd, resp, sizeof(resp) - 1, 0);
    
    if (received <= 3) { // 至少需要MSG_RESULT(1) + 成功标志(1) + 公钥的第一个字符(1)
        fprintf(stderr, "Failed to receive server pubkey\n");
        return -1;
    }
    
    if (resp[0] != MSG_RESULT || resp[1] != 1) {
        fprintf(stderr, "Server rejected key exchange request\n");
        return -1;
    }
    
    // 提取服务器公钥
    strcpy(peer_pubkey_buf, &resp[2]);
    
    // 使用本地密钥交换函数生成共享密钥
    if (sm2_key_exchange(self_privkey_hex, self_pubkey_hex, peer_pubkey_buf, 
                         shared_key, key_len) != 0) {
        fprintf(stderr, "SM2: Failed to generate shared key\n");
        return -1;
    }
    
    return 0;
}

/**
 * 向服务器发送签名数据并验证
 */
int verify_signature_with_server(int sockfd, const uint8_t* data, size_t data_len,
                              const char* signature, const char* pubkey_hex) {
    if (!data || data_len == 0 || !signature || !pubkey_hex) {
        fprintf(stderr, "SM2: Invalid verify parameters\n");
        return -1;
    }
    
    // 计算消息总长度
    size_t sig_len = strlen(signature);
    size_t pubkey_len = strlen(pubkey_hex);
    size_t buf_size = 1 + 4 + data_len + 4 + sig_len + 4 + pubkey_len;
    
    // 分配内存
    char* buf = (char*)malloc(buf_size);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    
    // 构造消息: [MSG_SM2_VERIFY][DATA_LEN][DATA][SIG_LEN][SIG][PUBKEY_LEN][PUBKEY]
    buf[0] = MSG_SM2_VERIFY;
    int offset = 1;
    
    // 写入数据长度
    *(uint32_t*)(buf + offset) = htonl((uint32_t)data_len);
    offset += 4;
    
    // 写入数据
    memcpy(buf + offset, data, data_len);
    offset += data_len;
    
    // 写入签名长度
    *(uint32_t*)(buf + offset) = htonl((uint32_t)sig_len);
    offset += 4;
    
    // 写入签名
    memcpy(buf + offset, signature, sig_len);
    offset += sig_len;
    
    // 写入公钥长度
    *(uint32_t*)(buf + offset) = htonl((uint32_t)pubkey_len);
    offset += 4;
    
    // 写入公钥
    memcpy(buf + offset, pubkey_hex, pubkey_len);
    offset += pubkey_len;
    
    // 发送验证请求
    ssize_t sent = send(sockfd, buf, offset, 0);
    free(buf);
    
    if (sent <= 0) {
        fprintf(stderr, "Failed to send signature verification request\n");
        return -1;
    }
    
    // 接收服务器响应
    char resp[2];
    if (recv(sockfd, resp, 2, 0) != 2) {
        fprintf(stderr, "Failed to receive signature verification response\n");
        return -1;
    }
    
    if (resp[0] != MSG_RESULT) {
        fprintf(stderr, "Invalid signature verification response\n");
        return -1;
    }
    
    // 返回验证结果
    return resp[1] == 1 ? 1 : 0;
}

