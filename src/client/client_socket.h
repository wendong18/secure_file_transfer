#ifndef CLIENT_SOCKET_H
#define CLIENT_SOCKET_H

#define MSG_LOGIN         0x01
#define MSG_RESULT        0x02
#define MSG_UPLOAD        0x03
#define MSG_UPLOAD_ACK    0x05
#define MSG_DOWNLOAD      0x04
#define MSG_DOWNLOAD_OK   0x06
#define MSG_DOWNLOAD_DATA 0x07
#define MSG_DOWNLOAD_END  0x08
#define MSG_LIST_FILES    0x09
#define MSG_GET_LOGS      0x0B
#define MSG_LOGS_RESP     0x0C
#define MSG_CHANGE_PASS   0x11  // 修改: 修改密码命令
#define MSG_DELETE_FILE   0x0E  // 新增: 删除文件命令
#define MSG_SEARCH_FILES  0x10  // 修改: 搜索文件命令
#define MSG_USER_MANAGE   0x0D  // 用户管理命令
#define MSG_DELETE_USER   0x0F  // 删除用户命令

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
 * @brief 修改用户密码
 * @param sockfd 已连接的 socket 描述符
 * @param username 用户名
 * @param old_password 旧密码
 * @param new_password 新密码
 * @return 成功返回0，失败返回-1
 */
int change_password(int sockfd, const char* username, const char* old_password, const char* new_password);

/**
 * @brief 删除文件
 * @param sockfd 已连接的 socket 描述符
 * @param filename 要删除的文件名
 * @return 成功返回0，失败返回-1
 */
int delete_file(int sockfd, const char* filename);

/**
 * @brief 搜索文件
 * @param sockfd 已连接的 socket 描述符
 * @param keyword 搜索关键词
 * @param result 结果输出缓冲区（JSON字符串）
 * @param maxlen 缓冲区最大长度
 * @return 找到的文件数，失败返回-1
 */
int search_files(int sockfd, const char* keyword, char* result, int maxlen);

/**
 * @brief 获取用户列表（仅管理员可用）
 * @param sockfd 已连接的 socket 描述符
 * @param result 结果输出缓冲区（JSON字符串）
 * @param maxlen 缓冲区最大长度
 * @return 用户数，失败返回-1
 */
int get_user_list(int sockfd, char* result, int maxlen);

/**
 * @brief 删除用户（仅限管理员）
 * @param sockfd 已连接的 socket 描述符
 * @param username 要删除的用户名
 * @return 成功返回0，失败返回-1
 */
int delete_user(int sockfd, const char* username);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_SOCKET_H 