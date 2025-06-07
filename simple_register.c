#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <time.h>

#define DB_PATH "secure.db"
#define SALT_LEN 16
#define HASH_LEN 65
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64

// 简单的生成盐值函数，避免使用复杂的OpenSSL函数
void simple_generate_salt(char* salt, int length) {
    if (!salt || length <= 0) return;
    
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int charset_size = sizeof(charset) - 1;
    
    // 使用简单的时间种子
    srand((unsigned int)time(NULL));
    
    // 生成随机盐值
    for (int i = 0; i < length; i++) {
        salt[i] = charset[rand() % charset_size];
    }
    salt[length] = '\0';
    
    printf("生成的盐值: %s\n", salt);
}

// 简单的密码哈希函数，使用简单的加盐方式
void simple_hash_password(const char* password, const char* salt, char* output_hash) {
    if (!password || !salt || !output_hash) return;
    
    // 简单地将盐值和密码拼接作为哈希结果
    // 注意：这不是安全的哈希方法，仅用于测试
    sprintf(output_hash, "%s_%s_hashed", salt, password);
    
    printf("生成的哈希: %s\n", output_hash);
}

// 检查用户名是否存在
int check_user_exists(const char* username) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int exists = 0;
    
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        printf("无法打开数据库: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    const char* sql = "SELECT 1 FROM Users WHERE username = ?";
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

// 创建数据库表
void init_db() {
    sqlite3* db;
    char* err_msg = NULL;
    
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        printf("无法打开数据库: %s\n", sqlite3_errmsg(db));
        return;
    }
    
    // 先删除旧表
    const char* drop_sql = "DROP TABLE IF EXISTS Users;";
    if (sqlite3_exec(db, drop_sql, 0, 0, &err_msg) != SQLITE_OK) {
        printf("SQL错误(删除旧表): %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    
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

// 注册用户
int register_user(const char* username, const char* password) {
    if (!username || !password || strlen(username) < 3 || strlen(password) < 6) {
        printf("无效的用户名或密码\n");
        return -1;
    }
    
    printf("注册用户: %s, 密码长度: %lu\n", username, strlen(password));
    
    // 检查用户名是否存在
    if (check_user_exists(username) > 0) {
        printf("用户名 %s 已存在\n", username);
        return -2;
    }
    
    // 生成盐值和哈希
    char salt[SALT_LEN + 1] = {0};
    char hash[HASH_LEN] = {0};
    
    simple_generate_salt(salt, SALT_LEN);
    simple_hash_password(password, salt, hash);
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char time_str[64];
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
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
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

int main() {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    
    // 初始化数据库
    printf("初始化数据库...\n");
    init_db();
    
    printf("=== 用户注册 ===\n");
    
    printf("请输入用户名(3-64字符): ");
    scanf("%s", username);
    
    printf("请输入密码(6-64字符): ");
    scanf("%s", password);
    
    int result = register_user(username, password);
    
    if (result == 0) {
        printf("注册成功！\n");
    } else if (result == -2) {
        printf("用户名已存在，请选择其他用户名\n");
    } else {
        printf("注册失败，错误代码: %d\n", result);
    }
    
    return 0;
} 