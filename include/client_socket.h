// include/client_socket.h

#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#define MSG_UPLOAD        0x03
#define MSG_UPLOAD_ACK    0x05
#define MSG_DOWNLOAD      0x04
#define MSG_DOWNLOAD_OK   0x06
#define MSG_DOWNLOAD_DATA 0x07
#define MSG_DOWNLOAD_END  0x08
#define MSG_LIST_FILES    0x09
#define MSG_GET_LOGS      0x0B
#define MSG_LOGS_RESP     0x0C
#define MSG_USER_MANAGE   0x0D
#define MSG_DELETE_FILE   0x0E
#define MSG_DELETE_USER   0x0F
#define MSG_SM2_PUBKEY    0x12  // 客户端发送SM2公钥
#define MSG_SM2_KEYX      0x13  // 密钥交换
#define MSG_SM2_SIGN      0x14  // 数字签名
#define MSG_SM2_VERIFY    0x15  // 签名验证

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 连接到服务器
 * @param ip    服务器 IP 地址（例如 "127.0.0.1"）
 * @param port  服务器端口号
 * @return 成功返回 socket 描述符，失败返回 -1
 */
int connect_to_server(const char* ip, int port);

/**
 * @brief 发送登录请求并接收结果
 * @param sockfd     由 connect_to_server 返回的 socket 描述符
 * @param username   用户名字符串
 * @param password   密码字符串
 * @return 登录成功返回 1，失败返回 0
 */
int login(int sockfd, const char* username, const char* password);

/**
 * @brief 上传本地文件到服务器
 * @param sockfd        已连接的 socket 描述符
 * @param local_path    本地文件路径
 * @param remote_name   在服务器上保存的文件名
 * @return 上传成功返回 0，失败返回 -1
 */
int upload_file(int sockfd, const char* local_path, const char* remote_name);

/**
 * @brief 上传本地文件到服务器（带访问权限参数）
 * @param sockfd        已连接的 socket 描述符
 * @param local_path    本地文件路径
 * @param remote_name   在服务器上保存的文件名
 * @param access_level  访问权限（"private", "public", "admin-only"）
 * @return 上传成功返回 0，失败返回 -1
 */
int upload_file_with_access(int sockfd, const char* local_path, const char* remote_name, const char* access_level);

/**
 * @brief 从服务器下载文件到本地
 * @param sockfd        已连接的 socket 描述符
 * @param remote_name   服务器上文件名
 * @param local_path    本地保存路径
 * @return 下载成功返回 0，失败返回 -1
 */
int download_file(int sockfd, const char* remote_name, const char* local_path);

/**
 * @brief 获取当前用户的文件列表
 * @param sockfd 已连接的 socket 描述符
 * @param result 结果输出缓冲区（JSON字符串）
 * @param maxlen 缓冲区最大长度
 * @return 文件数，失败返回-1
 */
int get_file_list(int sockfd, char* result, int maxlen);

/**
 * @brief 获取日志
 * @param sockfd 已连接的 socket 描述符
 * @param result 结果输出缓冲区（JSON字符串）
 * @param maxlen 缓冲区最大长度
 * @return 成功返回日志条数，失败返回-1
 */
int get_logs(int sockfd, char* result, int maxlen);

/**
 * @brief 获取用户列表（仅限管理员）
 * @param sockfd 已连接的 socket 描述符
 * @param result 结果输出缓冲区（JSON字符串）
 * @param maxlen 缓冲区最大长度
 * @return 成功返回用户数，失败返回-1
 */
int get_user_list(int sockfd, char* result, int maxlen);

/**
 * @brief 删除用户（仅限管理员）
 * @param sockfd 已连接的 socket 描述符
 * @param username 要删除的用户名
 * @return 成功返回0，失败返回-1
 */
int delete_user(int sockfd, const char* username);

/**
 * @brief 管理员删除文件（无视权限限制）
 * @param sockfd 已连接的 socket 描述符
 * @param filename 要删除的文件名
 * @return 成功返回0，失败返回-1
 */
int admin_delete_file(int sockfd, const char* filename);

/**
 * @brief 修改用户角色（仅限管理员）
 * @param sockfd 已连接的 socket 描述符
 * @param username 要修改的用户名
 * @param role 新角色（"admin"或"user"）
 * @return 成功返回0，失败返回-1
 */
int change_user_role(int sockfd, const char* username, const char* role);

/**
 * @brief 将用户SM2公钥上传到服务器
 * @param sockfd 已连接的 socket 描述符
 * @param pubkey_hex SM2公钥的十六进制字符串
 * @return 成功返回0，失败返回-1
 */
int upload_sm2_pubkey(int sockfd, const char* pubkey_hex);

/**
 * @brief 执行SM2密钥交换
 * @param sockfd 已连接的 socket 描述符
 * @param self_privkey_hex 本方私钥
 * @param self_pubkey_hex 本方公钥
 * @param peer_pubkey_buf 输出参数，保存对方公钥
 * @param shared_key 输出参数，保存生成的共享密钥
 * @param key_len 共享密钥长度
 * @return 成功返回0，失败返回-1
 */
int sm2_key_exchange_with_server(int sockfd, const char* self_privkey_hex, 
                                 const char* self_pubkey_hex, char* peer_pubkey_buf,
                                 uint8_t* shared_key, size_t key_len);

/**
 * @brief 向服务器发送签名数据并验证
 * @param sockfd 已连接的 socket 描述符
 * @param data 原始数据
 * @param data_len 数据长度
 * @param signature 签名
 * @param pubkey_hex 公钥
 * @return 验证成功返回1，失败返回0，错误返回-1
 */
int verify_signature_with_server(int sockfd, const uint8_t* data, size_t data_len,
                                const char* signature, const char* pubkey_hex);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_SOCKET_H

