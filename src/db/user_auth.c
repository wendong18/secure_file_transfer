// src/db/user_auth.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <time.h>
#include "../../include/common.h"
#include "../../include/user_auth.h"

/**
 * 检查用户名是否已存在
 */
int check_username_exists(const char* username) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int exists = 0;
    
    // 打开数据库
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 准备SQL语句
    const char *sql = "SELECT 1 FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "准备SQL语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    // 执行查询
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = 1;
    }
    
    // 清理
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return exists;
}

/**
 * 注册用户 - 修复版本
 */
int register_user(const char* username, const char* password) {
    if (!username || !password) {
        fprintf(stderr, "错误: 用户名或密码为空\n");
        return -1;
    }
    
    // 防止使用过长的输入
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    
    if (username_len < 3 || username_len >= MAX_USERNAME_LEN) {
        fprintf(stderr, "错误: 用户名长度必须在3到%d个字符之间\n", MAX_USERNAME_LEN-1);
        return -1;
    }
    
    if (password_len < 6 || password_len >= MAX_PASSWORD_LEN) {
        fprintf(stderr, "错误: 密码长度必须在6到%d个字符之间\n", MAX_PASSWORD_LEN-1);
        return -1;
    }
    
    // 检查是否尝试注册admin用户名
    if (strcasecmp(username, "admin") == 0) {
        fprintf(stderr, "错误: 不允许注册管理员用户名 'admin'\n");
        return -3;  // 特殊错误码表示尝试注册保留的用户名
    }
    
    // 检查用户名是否包含非法字符（只允许字母、数字和下划线）
    for (size_t i = 0; i < username_len; i++) {
        char c = username[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '_')) {
            fprintf(stderr, "错误: 用户名只能包含字母、数字和下划线\n");
            return -1;
        }
    }
    
    // 检查用户名是否已存在
    int exists = check_username_exists(username);
    if (exists < 0) {
        fprintf(stderr, "错误: 检查用户名时发生数据库错误\n");
        return -1;
    }
    if (exists > 0) {
        fprintf(stderr, "用户名 %s 已存在\n", username);
        return -2;
    }
    
    // 初始化变量，确保所有内存都被正确初始化
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char salt[SALT_LEN+1] = {0};
    char hash[HASH_LEN+1] = {0}; // 增加一个字节确保总是有空终止符
    int result = -1;
    
    // 打开数据库连接
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    // 生成盐值和密码哈希
    generate_salt(salt, SALT_LEN);
    
    // 确保盐值正确生成
    if (strlen(salt) != SALT_LEN) {
        fprintf(stderr, "错误: 盐值生成失败，长度不正确\n");
        sqlite3_close(db);
        return -1;
    }
    
    // 哈希密码
    hash_password(password, salt, hash);
    
    // 确保哈希值正确生成
    if (strlen(hash) < 10) {
        fprintf(stderr, "错误: 密码哈希生成失败\n");
        sqlite3_close(db);
        return -1;
    }
    
    // 准备SQL查询 - 移除对role列的引用
    const char *sql = "INSERT INTO users (username, password_hash, salt, register_time) VALUES (?, ?, ?, datetime('now'));";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "准备SQL语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, salt, -1, SQLITE_STATIC) != SQLITE_OK) {
        
        fprintf(stderr, "绑定参数失败: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    // 执行插入
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "插入用户失败: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    // 操作成功
    fprintf(stderr, "用户 %s 注册成功\n", username);
    result = 0;
    
    // 清理资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return result;
}

/**
 * 登录验证 - 修复版本
 */
int login_user(const char* username, const char* password) {
    if (!username || !password) {
        fprintf(stderr, "错误: 用户名或密码为空\n");
        return 0;
    }
    
    // 检查输入长度
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    
    if (username_len < 1 || username_len >= MAX_USERNAME_LEN || 
        password_len < 1 || password_len >= MAX_PASSWORD_LEN) {
        fprintf(stderr, "错误: 用户名或密码长度无效\n");
        return 0;
    }
    
    fprintf(stderr, "验证用户登录: %s\n", username);
    
    // 初始化变量
    sqlite3* db = NULL;
    sqlite3_stmt* stmt = NULL;
    int success = 0;
    
    // 打开数据库
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    
    // 准备SQL查询
    const char* sql = "SELECT user_id, password_hash, salt FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "准备SQL语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    // 绑定参数
    if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        fprintf(stderr, "绑定参数失败: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }
    
    // 执行查询
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int user_id = sqlite3_column_int(stmt, 0);
        const char* stored_hash = (const char*)sqlite3_column_text(stmt, 1);
        const char* salt = (const char*)sqlite3_column_text(stmt, 2);
        
        if (!stored_hash || !salt) {
            fprintf(stderr, "错误: 数据库中的哈希或盐值为空\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }
        
        // 计算哈希并验证
        char computed_hash[HASH_LEN+1] = {0}; // 确保有足够空间
        hash_password(password, salt, computed_hash);
        
        if (strlen(computed_hash) < 10 || strcmp(computed_hash, "ERROR") == 0) {
            fprintf(stderr, "错误: 哈希计算失败\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }
        
        // 比较哈希值
        if (strcmp(stored_hash, computed_hash) == 0) {
            success = 1;
            fprintf(stderr, "用户 '%s' (ID: %d) 登录成功\n", username, user_id);
            
            // 简化的日志记录，使用SQL而不是预处理语句
            char log_sql[256];
            snprintf(log_sql, sizeof(log_sql), 
                     "INSERT INTO Logs (user_id, username, op_type, op_time) "
                     "VALUES (%d, '%s', 'login', datetime('now'));", 
                     user_id, username);
            
            sqlite3_exec(db, log_sql, NULL, NULL, NULL);
        } else {
            fprintf(stderr, "用户 '%s' 密码不匹配\n", username);
        }
    } else {
        fprintf(stderr, "用户 '%s' 不存在\n", username);
    }

    // 清理资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return success;
}

/**
 * 根据用户名查询 user_id
 */
int get_user_id(const char* username) {
    sqlite3* db;
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "[AUTH] Cannot open DB: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    const char* sql = "SELECT user_id FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    int uid = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        uid = sqlite3_column_int(stmt, 0);
    } else {
        fprintf(stderr, "[AUTH] get_user_id: '%s' not found\n", username);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return uid;
}

int is_admin(int user_id) {
    sqlite3* db = NULL;
    sqlite3_open("secure_file_transfer.db", &db);
    if (!db) return 0;
    
    const char* sql = "SELECT username FROM users WHERE user_id=?;";
    sqlite3_stmt* stmt = NULL;
    int admin = 0;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)==SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, user_id);
        if (sqlite3_step(stmt)==SQLITE_ROW) {
            const char* username = (const char*)sqlite3_column_text(stmt, 0);
            // 只有用户名为"admin"的用户才是管理员，不依赖role列
            if (username && strcasecmp(username, "admin")==0) {
                admin = 1;
                fprintf(stderr, "[AUTH] User ID %d is admin (username: %s)\n", user_id, username);
            } else {
                fprintf(stderr, "[AUTH] User ID %d is not admin (username: %s)\n", user_id, username ? username : "NULL");
            }
        } else {
            fprintf(stderr, "[AUTH] User ID %d not found\n", user_id);
        }
    } else {
        fprintf(stderr, "[AUTH] Failed to prepare SQL: %s\n", sqlite3_errmsg(db));
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return admin;
}

int register_user_with_pubkey(const char* username, const char* password, const char* sm2_pubkey) {
    char salt[SALT_LEN + 1];
    char hash[HASH_LEN];
    generate_salt(salt, SALT_LEN);
    hash_password(password, salt, hash);

    sqlite3* db;
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "[AUTH] Cannot open DB: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    const char* sql = "INSERT INTO users (username, password_hash, salt, sm2_pubkey) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash,     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt,     -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, sm2_pubkey, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[AUTH] register_user_with_pubkey failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    printf("[AUTH] User '%s' registered with pubkey.\n", username);
    return 0;
}

int get_user_pubkey(const char* username, char* pubkey_buf, int bufsize) {
    sqlite3* db;
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "[AUTH] Cannot open DB: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    const char* sql = "SELECT sm2_pubkey FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int rc = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* pk = (const char*)sqlite3_column_text(stmt, 0);
        if (pk && pubkey_buf && bufsize > 0) {
            strncpy(pubkey_buf, pk, bufsize-1);
            pubkey_buf[bufsize-1] = '\0';
            rc = 0;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

/**
 * 验证用户登录 - 改进版本
 */
int verify_user(const char* username, const char* password, int* user_id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int success = 0;
    
    // 1. 参数验证
    if (!username || !password || !user_id) {
        fprintf(stderr, "错误: verify_user函数参数无效\n");
        return 0;
    }
    
    // 设置初始用户ID为-1（表示未找到）
    *user_id = -1;
    
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    
    if (username_len < 1 || username_len > MAX_USERNAME_LEN - 1 || 
        password_len < 1 || password_len > MAX_PASSWORD_LEN - 1) {
        fprintf(stderr, "错误: 用户名或密码长度无效\n");
        return 0;
    }
    
    fprintf(stderr, "验证用户: %s, 密码长度: %lu\n", username, password_len);
    
    // 2. 打开数据库
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "无法打开数据库: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    
    // 3. 准备SQL查询
    const char *sql = "SELECT user_id, password_hash, salt FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "准备SQL语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    // 4. 绑定参数
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    // 5. 执行查询
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // 获取用户ID和凭据
        *user_id = sqlite3_column_int(stmt, 0);
        const char *stored_hash = (const char*)sqlite3_column_text(stmt, 1);
        const char *salt = (const char*)sqlite3_column_text(stmt, 2);
        
        if (!stored_hash || !salt) {
            fprintf(stderr, "错误: 数据库中的哈希或盐值为空\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }
        
        fprintf(stderr, "找到用户 %s，ID: %d\n", username, *user_id);
        
        // 6. 使用相同的盐值哈希输入的密码
        char computed_hash[HASH_LEN] = {0};
        hash_password(password, salt, computed_hash);
        
        if (strlen(computed_hash) < 10) {
            fprintf(stderr, "错误: 哈希计算失败\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }
        
        // 7. 比较哈希值
        if (strcmp(stored_hash, computed_hash) == 0) {
            success = 1;
            fprintf(stderr, "用户 %s 密码验证成功\n", username);
            
            // 记录验证成功日志
            char log_sql[200];
            sprintf(log_sql, "INSERT INTO Logs (user_id, username, op_type, op_time) VALUES (%d, '%s', 'verify', CURRENT_TIMESTAMP);", 
                    *user_id, username);
            
            if (sqlite3_exec(db, log_sql, NULL, NULL, NULL) != SQLITE_OK) {
                fprintf(stderr, "警告: 无法记录验证日志\n");
            }
        } else {
            fprintf(stderr, "用户 %s 密码验证失败\n", username);
            
            #ifdef DEBUG
            // 调试模式下输出详细信息，但生产环境中不应该这样做
            fprintf(stderr, "存储的哈希: %s\n", stored_hash);
            fprintf(stderr, "计算的哈希: %s\n", computed_hash);
            #endif
        }
    } else {
        fprintf(stderr, "未找到用户 %s\n", username);
    }
    
    // 8. 清理资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return success;
}

/**
 * 根据用户ID获取用户名
 */
char* get_username_by_id(int user_id, char* username_buf, int buf_size) {
    if (!username_buf || buf_size <= 0) {
        return NULL;
    }
    
    // 默认将缓冲区第一个字符设为0，表示未找到
    username_buf[0] = '\0';
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    
    // 打开数据库
    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    
    // 准备SQL语句
    const char* sql = "SELECT username FROM users WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    
    // 绑定参数
    sqlite3_bind_int(stmt, 1, user_id);
    
    // 执行查询
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* username = sqlite3_column_text(stmt, 0);
        if (username) {
            strncpy(username_buf, (const char*)username, buf_size - 1);
            username_buf[buf_size - 1] = '\0';
        }
    }
    
    // 清理
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return username_buf[0] ? username_buf : NULL;
}

/**
 * 删除用户
 */
int delete_user(int user_id) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int result = -1;
    
    // 打开数据库
    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 开始事务
    if (sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to begin transaction: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 首先获取用户的所有文件信息，用于后续删除物理文件
    const char* sql_get_files = "SELECT filename FROM files WHERE user_id = ?;";
    sqlite3_stmt* files_stmt;
    
    if (sqlite3_prepare_v2(db, sql_get_files, -1, &files_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare get files statement: %s\n", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_int(files_stmt, 1, user_id);
    
    // 存储文件名，用于后续删除物理文件
    char filenames[100][256] = {0}; // 最多存储100个文件名
    int file_count = 0;
    
    while (sqlite3_step(files_stmt) == SQLITE_ROW && file_count < 100) {
        const char* filename = (const char*)sqlite3_column_text(files_stmt, 0);
        if (filename) {
            strncpy(filenames[file_count], filename, 255);
            filenames[file_count][255] = '\0';
            file_count++;
        }
    }
    
    sqlite3_finalize(files_stmt);
    
    // 准备删除用户SQL语句
    const char* sql_delete_user = "DELETE FROM users WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db, sql_delete_user, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare delete user statement: %s\n", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    sqlite3_bind_int(stmt, 1, user_id);
    
    // 执行删除
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete user: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    
    // 删除用户相关的文件记录
    const char* sql_delete_files = "DELETE FROM files WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db, sql_delete_files, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare delete files statement: %s\n", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    sqlite3_bind_int(stmt, 1, user_id);
    
    // 执行删除
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete user files: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    
    // 提交事务
    if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to commit transaction: %s\n", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        sqlite3_close(db);
        return -1;
    }
    
    // 删除物理文件
    for (int i = 0; i < file_count; i++) {
        char filepath[512] = {0};
        snprintf(filepath, sizeof(filepath), "uploads/%s", filenames[i]);
        fprintf(stderr, "Deleting physical file: %s\n", filepath);
        if (remove(filepath) != 0) {
            fprintf(stderr, "Warning: Failed to delete physical file: %s\n", filepath);
            // 继续删除其他文件，不中断操作
        }
    }
    
    result = 0;
    sqlite3_close(db);
    return result;
}

/**
 * 验证用户密码
 */
int verify_password(int user_id, const char* password) {
    if (!password) {
        return 0;
    }
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    int success = 0;
    
    // 打开数据库
    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    // 准备SQL语句
    const char* sql = "SELECT password_hash, salt FROM users WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    // 绑定参数
    sqlite3_bind_int(stmt, 1, user_id);
    
    // 执行查询
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* stored_hash = (const char*)sqlite3_column_text(stmt, 0);
        const char* salt = (const char*)sqlite3_column_text(stmt, 1);
        
        if (stored_hash && salt) {
            // 计算密码哈希
            char computed_hash[HASH_LEN] = {0};
            hash_password(password, salt, computed_hash);
            
            // 比较哈希值
            if (strcmp(stored_hash, computed_hash) == 0) {
                success = 1;
            }
        }
    }
    
    // 清理
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return success;
}

/**
 * 更新用户密码
 */
int update_password(int user_id, const char* new_password) {
    if (!new_password) {
        return -1;
    }
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    int result = -1;
    
    // 打开数据库
    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 生成新的盐值
    char salt[SALT_LEN + 1] = {0};
    generate_salt(salt, SALT_LEN);
    
    // 计算新密码的哈希值
    char hash[HASH_LEN] = {0};
    hash_password(new_password, salt, hash);
    
    // 准备SQL语句
    const char* sql = "UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, salt, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, user_id);
    
    // 执行更新
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to update password: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    // 检查是否有行被更新
    if (sqlite3_changes(db) > 0) {
        result = 0;
    }
    
    // 清理
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return result;
}

