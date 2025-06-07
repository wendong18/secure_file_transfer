// src/db/db_init.c

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../../include/common.h"

/**
 * @brief 初始化 SQLite 数据库并创建必要表格
 *        - Users 表用于存储用户信息
 *        - Files 表用于存储文件信息，并新增 user_id 外键
 */
void init_db() {
    sqlite3* db;
    char* err_msg = NULL;

    // 打开（或创建）数据库
    if (sqlite3_open(DB_PATH, &db)) {
        fprintf(stderr, "Cannot open DB: %s\n", sqlite3_errmsg(db));
        return;
    }

    // 1. 创建 Users 表
    const char* user_table_sql =
        "CREATE TABLE IF NOT EXISTS Users ("
        "   user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   username TEXT UNIQUE NOT NULL,"
        "   password_hash TEXT NOT NULL,"
        "   salt TEXT NOT NULL,"
        "   sm2_pubkey TEXT,"
        "   register_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";
    if (sqlite3_exec(db, user_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error (Users): %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("[DB] 用户表初始化成功。\n");
    }

    // 2. 创建 Files 表，新增 user_id 外键
    const char* file_table_sql =
        "CREATE TABLE IF NOT EXISTS Files ("
        "   file_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   filename TEXT NOT NULL,"
        "   upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "   file_path TEXT NOT NULL,"
        "   access_level TEXT DEFAULT 'private',"
        "   user_id INTEGER,"
        "   FOREIGN KEY(user_id) REFERENCES Users(user_id)"
        ");";
    if (sqlite3_exec(db, file_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error (Files): %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("[DB] 文件表初始化成功，包含 user_id 外键。\n");
    }

    // 3. 创建 Logs 表
    const char* log_table_sql =
        "CREATE TABLE IF NOT EXISTS Logs ("
        "   log_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   user_id INTEGER,"
        "   username TEXT,"
        "   op_type TEXT,"
        "   file_name TEXT,"
        "   ip TEXT,"
        "   op_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";
    if (sqlite3_exec(db, log_table_sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error (Logs): %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("[DB] 日志表初始化成功。\n");
    }

    // 关闭数据库
    sqlite3_close(db);
}

/**
 * 初始化数据库，创建必要的表和目录
 * @return 成功返回0，失败返回非0值
 */
int init_database() {
    sqlite3 *db;
    char *err_msg = 0;
    int rc;
    
    // 打开数据库
    rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 创建用户表
    const char *sql_users = "CREATE TABLE IF NOT EXISTS users ("
                           "user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                           "username TEXT NOT NULL UNIQUE,"
                           "password_hash TEXT NOT NULL,"
                           "salt TEXT NOT NULL,"
                           "role TEXT DEFAULT 'user',"
                           "register_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                           ");";
    
    rc = sqlite3_exec(db, sql_users, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }
    
    // 创建文件表
    const char *sql_files = "CREATE TABLE IF NOT EXISTS files ("
                           "file_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                           "filename TEXT NOT NULL,"
                           "path TEXT NOT NULL,"
                           "user_id INTEGER NOT NULL,"
                           "access_level TEXT DEFAULT 'private',"
                           "upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,"
                           "FOREIGN KEY (user_id) REFERENCES users(user_id)"
                           ");";
    
    rc = sqlite3_exec(db, sql_files, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }
    
    // 创建日志表
    const char *sql_logs = "CREATE TABLE IF NOT EXISTS logs ("
                          "log_id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "op_time DATETIME DEFAULT CURRENT_TIMESTAMP,"
                          "op_type TEXT NOT NULL,"
                          "file_name TEXT,"
                          "ip TEXT,"
                          "user_id INTEGER,"
                          "username TEXT,"
                          "FOREIGN KEY (user_id) REFERENCES users(user_id)"
                          ");";
    
    rc = sqlite3_exec(db, sql_logs, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }
    
    // 检查是否已存在admin用户
    sqlite3_stmt *stmt = NULL;
    const char *check_admin_sql = "SELECT COUNT(*) FROM users WHERE username = 'admin';";
    int admin_exists = 0;
    
    if (sqlite3_prepare_v2(db, check_admin_sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            admin_exists = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    // 检查users表的结构，查看是否有role列
    int has_role_column = 0;
    const char *check_schema_sql = "PRAGMA table_info(users);";
    if (sqlite3_prepare_v2(db, check_schema_sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *column_name = (const char*)sqlite3_column_text(stmt, 1);
            if (column_name && strcmp(column_name, "role") == 0) {
                has_role_column = 1;
                break;
            }
        }
        sqlite3_finalize(stmt);
    }
    
    printf("表结构检查: role列%s存在\n", has_role_column ? "" : "不");
    
    // 如果admin用户不存在，则创建默认管理员账号
    if (!admin_exists) {
        printf("创建默认管理员账号: admin/admin123\n");
        
        // 生成盐值和密码哈希
        char salt[17] = "S4ltF0rAdm1nPwd"; // 固定盐值，用于admin账号
        char hash[65] = {0};
        
        // 使用用户认证模块的哈希函数
        extern void hash_password(const char* password, const char* salt, char* output_hash);
        hash_password("admin123", salt, hash);
        
        // 插入管理员用户 - 根据表结构选择正确的SQL
        const char *insert_admin_sql;
        if (has_role_column) {
            insert_admin_sql = "INSERT INTO users (username, password_hash, salt, role) "
                              "VALUES ('admin', ?, ?, 'admin');";
        } else {
            insert_admin_sql = "INSERT INTO users (username, password_hash, salt) "
                              "VALUES ('admin', ?, ?);";
        }
        
        sqlite3_stmt *insert_stmt = NULL;
        if (sqlite3_prepare_v2(db, insert_admin_sql, -1, &insert_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(insert_stmt, 1, hash, -1, SQLITE_STATIC);
            sqlite3_bind_text(insert_stmt, 2, salt, -1, SQLITE_STATIC);
            
            if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
                fprintf(stderr, "创建管理员账号失败: %s\n", sqlite3_errmsg(db));
            } else {
                printf("管理员账号创建成功\n");
            }
            
            sqlite3_finalize(insert_stmt);
        } else {
            fprintf(stderr, "准备插入管理员SQL失败: %s\n", sqlite3_errmsg(db));
        }
    } else {
        printf("管理员账号已存在\n");
    }
    
    // 确保uploads目录存在
    struct stat st = {0};
    if (stat("uploads", &st) == -1) {
        #ifdef _WIN32
        mkdir("uploads");
        #else
        mkdir("uploads", 0700);
        #endif
        fprintf(stderr, "Created uploads directory\n");
    }
    
    // 关闭数据库
    sqlite3_close(db);
    return 0;
}

