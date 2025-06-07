#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#define DB_PATH "secure.db"
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define SALT_LEN 16
#define HASH_LEN 65

// 生成随机盐值
void generate_salt(char* salt, int length) {
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int charset_size = sizeof(charset) - 1;
    
    // 使用时间作为种子
    srand((unsigned int)time(NULL));
    
    // 生成随机盐值
    for (int i = 0; i < length; i++) {
        salt[i] = charset[rand() % charset_size];
    }
    salt[length] = '\0';
    
    printf("生成的盐值: %s\n", salt);
}

// 简单的密码哈希函数
void hash_password(const char* password, const char* salt, char* output_hash) {
    // 简单地将盐值和密码拼接作为哈希结果
    sprintf(output_hash, "%s_%s_hashed", salt, password);
    printf("生成的哈希: %s\n", output_hash);
}

// 初始化数据库
void init_db() {
    sqlite3* db;
    char* err_msg = NULL;
    
    // 打开数据库
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        printf("无法打开数据库: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }
    
    // 先删除旧表
    const char* drop_sql = "DROP TABLE IF EXISTS Users;";
    if (sqlite3_exec(db, drop_sql, 0, 0, &err_msg) != SQLITE_OK) {
        printf("SQL错误(删除旧表): %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
    // 创建用户表
    const char* sql = 
        "CREATE TABLE IF NOT EXISTS Users ("
        "   user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   username TEXT UNIQUE NOT NULL,"
        "   password_hash TEXT NOT NULL,"
        "   salt TEXT NOT NULL,"
        "   is_admin INTEGER DEFAULT 0,"
        "   register_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "   sm2_pubkey TEXT,"
        "   last_login TIMESTAMP"
        ");";
    
    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        printf("SQL错误: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("数据库表初始化成功\n");
    }
    
    sqlite3_close(db);
}

// 检查用户名是否存在
int check_username_exists(const char* username) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int exists = 0;
    
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        printf("无法打开数据库: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    const char* sql = "SELECT 1 FROM Users WHERE username = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf("准备SQL语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = 1;
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return exists;
}

// 注册新用户
int register_user(const char* username, const char* password) {
    // 检查参数
    if (!username || !password) {
        printf("无效的用户名或密码\n");
        return -1;
    }
    
    if (strlen(username) < 3 || strlen(password) < 6) {
        printf("用户名至少需要3个字符，密码至少需要6个字符\n");
        return -1;
    }
    
    printf("注册用户: %s, 密码长度: %lu\n", username, strlen(password));
    
    // 检查用户名是否存在
    if (check_username_exists(username) > 0) {
        printf("用户名 %s 已存在\n", username);
        return -2;
    }
    
    // 生成盐值和密码哈希
    char salt[SALT_LEN + 1] = {0};
    char hash[HASH_LEN] = {0};
    
    generate_salt(salt, SALT_LEN);
    hash_password(password, salt, hash);
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char time_str[64] = {0};
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
    
    // 插入用户记录
    sqlite3* db;
    sqlite3_stmt* stmt;
    
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        printf("无法打开数据库: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    const char* sql = "INSERT INTO Users (username, password_hash, salt, register_time) VALUES (?, ?, ?, ?);";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf("准备SQL语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, time_str, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt);
    if (result != SQLITE_DONE) {
        printf("插入用户失败: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    printf("用户 %s 注册成功\n", username);
    return 0;
}

// 用户登录验证
int login_user(const char* username, const char* password) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int success = 0;
    
    if (!username || !password) {
        printf("无效的用户名或密码\n");
        return 0;
    }
    
    printf("登录验证: %s\n", username);
    
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        printf("无法打开数据库: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    
    const char* sql = "SELECT password_hash, salt FROM Users WHERE username = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf("准备SQL语句失败: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* stored_hash = (const char*)sqlite3_column_text(stmt, 0);
        const char* salt = (const char*)sqlite3_column_text(stmt, 1);
        
        char computed_hash[HASH_LEN] = {0};
        hash_password(password, salt, computed_hash);
        
        if (strcmp(stored_hash, computed_hash) == 0) {
            success = 1;
            printf("登录成功: %s\n", username);
        } else {
            printf("密码不匹配: %s\n", username);
        }
    } else {
        printf("用户不存在: %s\n", username);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return success;
}

int main() {
    char username[MAX_USERNAME_LEN] = {0};
    char password[MAX_PASSWORD_LEN] = {0};
    char confirm_password[MAX_PASSWORD_LEN] = {0};
    int choice = 0;
    
    // 初始化数据库
    printf("初始化数据库...\n");
    init_db();
    
    do {
        printf("\n=== 安全文件传输系统 ===\n");
        printf("1. 注册新用户\n");
        printf("2. 用户登录\n");
        printf("0. 退出程序\n");
        printf("请选择操作: ");
        
        if (scanf("%d", &choice) != 1) {
            printf("输入无效，请重试\n");
            while (getchar() != '\n'); // 清除输入缓冲区
            continue;
        }
        
        while (getchar() != '\n'); // 清除输入缓冲区
        
        switch (choice) {
            case 1: // 注册
                printf("\n=== 用户注册 ===\n");
                
                printf("请输入用户名(3-64字符): ");
                scanf("%63s", username);
                
                printf("请输入密码(6-64字符): ");
                scanf("%63s", password);
                
                printf("请再次输入密码: ");
                scanf("%63s", confirm_password);
                
                while (getchar() != '\n'); // 清除输入缓冲区
                
                if (strcmp(password, confirm_password) != 0) {
                    printf("两次输入的密码不一致，注册失败\n");
                } else {
                    int result = register_user(username, password);
                    if (result == 0) {
                        printf("注册成功！\n");
                    } else if (result == -2) {
                        printf("用户名已存在，请选择其他用户名\n");
                    } else {
                        printf("注册失败，错误代码: %d\n", result);
                    }
                }
                break;
                
            case 2: // 登录
                printf("\n=== 用户登录 ===\n");
                
                printf("请输入用户名: ");
                scanf("%63s", username);
                
                printf("请输入密码: ");
                scanf("%63s", password);
                
                while (getchar() != '\n'); // 清除输入缓冲区
                
                if (login_user(username, password)) {
                    printf("登录成功！欢迎 %s\n", username);
                } else {
                    printf("登录失败，用户名或密码错误\n");
                }
                break;
                
            case 0:
                printf("程序退出\n");
                break;
                
            default:
                printf("无效选择，请重试\n");
        }
        
        if (choice != 0) {
            printf("\n按回车键继续...");
            getchar();
        }
    } while (choice != 0);
    
    return 0;
} 