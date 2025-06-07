// include/user_auth.h

#ifndef USER_AUTH_H
#define USER_AUTH_H

#include <stdbool.h>

/**
 * @brief 检查用户名是否已存在
 * @param username  用户名
 * @return 存在返回 1，不存在返回 0，错误返回 -1
 */
int check_username_exists(const char* username);

/**
 * @brief 注册新用户
 * @param username  用户名（唯一）
 * @param password  明文密码
 * @return 成功返回 0，失败返回负数，用户已存在返回-2
 */
int register_user(const char* username, const char* password);

/**
 * @brief 使用SM2公钥注册用户
 * @param username  用户名（唯一）
 * @param password  明文密码
 * @param sm2_pubkey  公钥HEX字符串
 * @return 成功返回 0，失败返回负数
 */
int register_user_with_pubkey(const char* username, const char* password, const char* sm2_pubkey);

/**
 * @brief 验证用户登录
 * @param username  用户名
 * @param password  明文密码
 * @return 登录成功返回 1，失败返回 0
 */
int login_user(const char* username, const char* password);

/**
 * @brief  根据用户名查询对应的 user_id
 * @param username  用户名
 * @return 若存在返回 user_id，否则返回 -1
 */
int get_user_id(const char* username);

/**
 * @brief 检查用户是否为管理员
 * @param user_id 用户ID
 * @return 是管理员返回1，否则返回0
 */
int is_admin(int user_id);

/**
 * @brief 获取用户的SM2公钥
 * @param username 用户名
 * @param pubkey_buf 公钥缓冲区
 * @param bufsize 缓冲区大小
 * @return 成功返回0，失败返回-1
 */
int get_user_pubkey(const char* username, char* pubkey_buf, int bufsize);

/**
 * @brief 验证用户并获取用户ID
 * @param username 用户名
 * @param password 密码
 * @param user_id 输出参数，存储用户ID
 * @return 成功返回1，失败返回0
 */
int verify_user(const char* username, const char* password, int* user_id);

/**
 * @brief 根据用户ID获取用户名
 * @param user_id 用户ID
 * @param username_buf 用户名缓冲区
 * @param buf_size 缓冲区大小
 * @return 成功返回用户名缓冲区指针，失败返回NULL
 */
char* get_username_by_id(int user_id, char* username_buf, int buf_size);

/**
 * @brief 删除用户
 * @param user_id 用户ID
 * @return 成功返回0，失败返回-1
 */
int delete_user(int user_id);

/**
 * @brief 验证用户密码
 * @param user_id 用户ID
 * @param password 密码
 * @return 密码正确返回1，错误返回0
 */
int verify_password(int user_id, const char* password);

/**
 * @brief 更新用户密码
 * @param user_id 用户ID
 * @param new_password 新密码
 * @return 成功返回0，失败返回-1
 */
int update_password(int user_id, const char* new_password);

#endif // USER_AUTH_H

