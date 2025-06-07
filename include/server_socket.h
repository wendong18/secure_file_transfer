// include/server_socket.h

#ifndef SERVER_SOCKET_H
#define SERVER_SOCKET_H

#include <stdint.h>

// —— 在这里定义所有消息类型 —— 
#define MSG_LOGIN         0x01
#define MSG_RESULT        0x02
#define MSG_UPLOAD        0x03
#define MSG_UPLOAD_ACK    0x05
#define MSG_DOWNLOAD      0x04
#define MSG_DOWNLOAD_OK   0x06
#define MSG_DOWNLOAD_END  0x08
#define MSG_LIST_FILES    0x09
#define MSG_LIST_FILES_RESP 0x0A
#define MSG_LIST_LOGS    0x0B
#define MSG_LIST_LOGS_RESP 0x0C
#define MSG_USER_MANAGE   0x0D
#define MSG_DELETE_FILE   0x0E
#define MSG_DELETE_USER   0x0F
#define MSG_SEARCH_FILES  0x10
#define MSG_CHANGE_PASS   0x11
#define MSG_SM2_PUBKEY    0x12  // 客户端发送SM2公钥
#define MSG_SM2_KEYX      0x13  // 密钥交换
#define MSG_SM2_SIGN      0x14  // 数字签名
#define MSG_SM2_VERIFY    0x15  // 签名验证

// 初始化、accept、处理连接的接口
int init_server_socket(int port);
int accept_client(int server_fd);
void handle_client(int client_fd);

#endif // SERVER_SOCKET_H

