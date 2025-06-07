#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

/**
 * 在数据库中登记新文件
 * @return 0 表示成功，-1 失败
 */
int add_file_record(const char* filename,
                    const char* filepath,
                    int owner_id,
                    const char* access_level);

/**
 * 检查 user_id 是否对 file_id 有访问权限
 * @return 1 有权限，0 无权限
 */
int check_file_permission(int file_id, int user_id);

/**
 * 获取指定用户的文件列表
 * @param user_id 用户ID
 * @param result 结果输出缓冲区（JSON字符串或自定义格式）
 * @param maxlen 缓冲区最大长度
 * @return 文件数，失败返回-1
 */
int list_user_files(int user_id, char* result, int maxlen);

/**
 * 从数据库中删除文件记录
 * @param file_id 文件ID
 * @return 0 表示成功，-1 失败
 */
int delete_file_record(int file_id);

/**
 * 添加操作日志
 */
int add_log(int user_id, const char* username, const char* op_type, const char* file_name, const char* ip);

/**
 * 查询日志
 * @param user_id 用户ID（管理员传-1）
 * @param is_admin 是否为管理员
 * @param result 输出缓冲区
 * @param maxlen 缓冲区最大长度
 * @return 日志条数，失败返回-1
 */
int list_logs(int user_id, int is_admin, char* result, int maxlen);

#endif // FILE_MANAGER_H
