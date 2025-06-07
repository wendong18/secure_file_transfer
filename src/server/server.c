#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include "../include/common.h"  // 添加common.h以使用hash_password函数

#define MSG_GET_LOGS      0x0B
#define MSG_LOGS_RESP     0x0C

int handle_list_files(int client_fd, int user_id) {
    char header[2] = {MSG_LIST_FILES_RESP, 1}; // 1表示成功
    
    // 查询数据库获取用户可访问的文件列表
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *err_msg = 0;
    
    // 打开数据库
    int rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 准备查询语句 - 获取用户可访问的文件
    // 这里简化为只获取用户自己上传的文件
    const char *sql = "SELECT filename, upload_time, access_level FROM Files WHERE user_id = ? OR access_level = 'public' ORDER BY upload_time DESC";
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 绑定用户ID参数
    sqlite3_bind_int(stmt, 1, user_id);
    
    // 构建JSON数组
    cJSON *root = cJSON_CreateArray();
    if (!root) {
        fprintf(stderr, "Failed to create JSON array\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 执行查询并处理结果
    int found_files = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        found_files++;
        const unsigned char *filename = sqlite3_column_text(stmt, 0);
        const unsigned char *upload_time = sqlite3_column_text(stmt, 1);
        const unsigned char *access_level = sqlite3_column_text(stmt, 2);
        
        // 创建文件对象
        cJSON *file = cJSON_CreateObject();
        if (file) {
            cJSON_AddStringToObject(file, "filename", (const char*)filename);
            cJSON_AddStringToObject(file, "upload_time", (const char*)upload_time);
            cJSON_AddStringToObject(file, "access_level", (const char*)access_level);
            
            // 添加到数组
            cJSON_AddItemToArray(root, file);
        } else {
            fprintf(stderr, "Failed to create file JSON object\n");
            // 继续处理其他文件
        }
    }
    
    fprintf(stderr, "Found %d files for user_id=%d, result: ", found_files, user_id);
    
    // 清理语句
    sqlite3_finalize(stmt);
    
    // 转换为JSON字符串
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        fprintf(stderr, "Failed to print JSON\n");
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    fprintf(stderr, "%s\n", json_str);
    
    // 发送响应头
    if (send(client_fd, header, 2, 0) != 2) {
        fprintf(stderr, "Failed to send response header\n");
        free(json_str);
        sqlite3_close(db);
        return -1;
    }
    
    fprintf(stderr, "Sending file list response header [%02x %02x]\n", (unsigned char)header[0], (unsigned char)header[1]);
    
    // 发送JSON数据
    size_t json_len = strlen(json_str);
    fprintf(stderr, "Sending file list data: %zu bytes\n", json_len);
    
    // 如果是空数组，则发送空数组字符串 "[]"
    if (found_files == 0) {
        const char *empty_array = "[]";
        json_len = 2;
        
        ssize_t n = send(client_fd, empty_array, json_len, 0);
        if (n <= 0) {
            fprintf(stderr, "Failed to send empty file list: %s\n", strerror(errno));
            free(json_str);
            sqlite3_close(db);
            return -1;
        }
    } else {
        ssize_t sent = 0;
        while (sent < json_len) {
            ssize_t n = send(client_fd, json_str + sent, json_len - sent, 0);
            if (n <= 0) {
                if (errno == EINTR) continue; // 被信号中断，重试
                fprintf(stderr, "Failed to send file list data: %s\n", strerror(errno));
                free(json_str);
                sqlite3_close(db);
                return -1;
            }
            sent += n;
        }
    }
    
    fprintf(stderr, "File list data sent successfully\n");
    
    // 记录日志
    fprintf(stderr, "Sent file list to user %d\n", user_id);
    
    // 清理
    free(json_str);
    sqlite3_close(db);
    
    return 0;
}

// 添加日志记录函数
int log_operation(const char* op_type, const char* filename, const char* ip, int user_id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *err_msg = 0;
    int rc;
    
    // 打开数据库
    rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
    
    // 使用参数化查询防止SQL注入
    const char *sql = "INSERT INTO Logs (op_time, op_type, file_name, ip, user_id) VALUES (?, ?, ?, ?, ?)";
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    sqlite3_bind_text(stmt, 1, time_str, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, op_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, filename ? filename : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, ip ? ip : "", -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, user_id);
    
    // 执行SQL
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    fprintf(stderr, "Log entry added: %s %s %s %s %d\n", time_str, op_type, filename ? filename : "(null)", ip ? ip : "(null)", user_id);
    
    // 清理
    sqlite3_finalize(stmt);
    
    // 关闭数据库
    sqlite3_close(db);
    return 0;
}

// 修改上传文件处理函数，添加日志记录
int handle_upload(int client_fd, int user_id) {
    // 接收文件名
    char filename[256] = {0};
    int i = 0;
    while (i < 255) {
        if (recv(client_fd, &filename[i], 1, 0) != 1) return -1;
        if (filename[i] == 0) break;
        i++;
    }
    
    fprintf(stderr, "Upload request for file '%s' from UID=%d\n", filename, user_id);
    
    // 接收文件大小
    uint64_t enc_size;
    if (recv(client_fd, &enc_size, 8, 0) != 8) return -1;
    enc_size = ntohll(enc_size);
    
    // 接收IV
    unsigned char iv[16];
    if (recv(client_fd, iv, 16, 0) != 16) return -1;
    
    // 接收访问权限
    char access_level[32] = {0};
    i = 0;
    while (i < 31) {
        if (recv(client_fd, &access_level[i], 1, 0) != 1) return -1;
        if (access_level[i] == 0) break;
        i++;
    }
    
    fprintf(stderr, "Access level specified: '%s'\n", access_level);
    
    // 接收加密数据
    unsigned char *enc_data = malloc(enc_size);
    if (!enc_data) return -1;
    
    size_t recvd = 0;
    while (recvd < enc_size) {
        ssize_t r = recv(client_fd, enc_data + recvd, enc_size - recvd, 0);
        if (r <= 0) { free(enc_data); return -1; }
        recvd += r;
    }
    
    fprintf(stderr, "Encrypted data length: %zu bytes\n", enc_size);
    fprintf(stderr, "Decrypting data...\n");
    
    // 解密数据
    unsigned char *dec_data = malloc(enc_size);
    if (!dec_data) { free(enc_data); return -1; }
    
    unsigned char key[16] = {0};  // 与客户端约定的密钥
    sm4_cbc_decrypt_wrapper(key, iv, enc_data, dec_data, enc_size);
    free(enc_data);
    
    // 去除填充
    size_t pad = dec_data[enc_size - 1];
    size_t orig_len = enc_size - pad;
    
    // 确保uploads目录存在
    struct stat st = {0};
    if (stat("uploads", &st) == -1) {
        #ifdef _WIN32
        mkdir("uploads");
        #else
        mkdir("uploads", 0700);
        #endif
    }
    
    // 构建文件路径
    char path[512] = {0};
    snprintf(path, sizeof(path), "uploads/%s", filename);
    
    // 写入文件
    fprintf(stderr, "Writing file to: %s\n", path);
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open file for writing: %s\n", path);
        free(dec_data);
        return -1;
    }
    
    fwrite(dec_data, 1, orig_len, fp);
    fclose(fp);
    free(dec_data);
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
    
    // 记录到数据库
    char sql[1024];
    sprintf(sql, "INSERT INTO Files (filename, path, user_id, access_level, upload_time) VALUES ('%s', '%s', %d, '%s', '%s')",
            filename, path, user_id, access_level, time_str);
    
    sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    fprintf(stderr, "Adding file record: filename=%s, path=%s, user_id=%d, access=%s\n", 
            filename, path, user_id, access_level);
    
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }
    
    fprintf(stderr, "File record inserted successfully with ID %lld\n", sqlite3_last_insert_rowid(db));
    fprintf(stderr, "File record added to database\n");
    
    // 获取客户端IP地址
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(client_fd, (struct sockaddr *)&addr, &addr_size);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    // 添加日志记录
    log_operation("上传", filename, client_ip, user_id);
    
    // 发送ACK
    char ack = MSG_UPLOAD_ACK;
    fprintf(stderr, "Sending upload ACK\n");
    if (send(client_fd, &ack, 1, 0) != 1) {
        fprintf(stderr, "Failed to send ACK\n");
        sqlite3_close(db);
        return -1;
    }
    
    fprintf(stderr, "Upload ACK sent successfully\n");
    fprintf(stderr, "Uploaded '%s' by UID=%d\n", filename, user_id);
    
    sqlite3_close(db);
    return 0;
}

// 处理获取日志请求
int handle_get_logs(int client_fd, int user_id) {
    char header[2] = {MSG_LOGS_RESP, 1}; // 1表示成功
    
    // 查询数据库获取日志列表
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *err_msg = 0;
    
    // 打开数据库
    int rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 准备查询语句 - 获取所有日志或与用户相关的日志
    const char *sql;
    if (user_id == 1) {  // 假设管理员ID为1，可以查看所有日志
        sql = "SELECT l.log_id, l.op_time, l.op_type, l.file_name, l.ip, l.username "
              "FROM logs l LEFT JOIN users u ON l.user_id = u.user_id "
              "ORDER BY l.op_time DESC LIMIT 100";
    } else {
        sql = "SELECT l.log_id, l.op_time, l.op_type, l.file_name, l.ip, l.username "
              "FROM logs l LEFT JOIN users u ON l.user_id = u.user_id "
              "WHERE l.user_id = ? OR (l.file_name IN (SELECT filename FROM files WHERE user_id = ?)) "
              "ORDER BY l.op_time DESC LIMIT 100";
    }
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 如果不是管理员，绑定用户ID参数
    if (user_id != 1) {
        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, user_id);
    }
    
    // 构建JSON数组
    cJSON *root = cJSON_CreateArray();
    if (!root) {
        fprintf(stderr, "Failed to create JSON array\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 执行查询并处理结果
    int found_logs = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        found_logs++;
        int log_id = sqlite3_column_int(stmt, 0);
        const unsigned char *op_time = sqlite3_column_text(stmt, 1);
        const unsigned char *op_type = sqlite3_column_text(stmt, 2);
        const unsigned char *file_name = sqlite3_column_text(stmt, 3);
        const unsigned char *ip = sqlite3_column_text(stmt, 4);
        const unsigned char *username = sqlite3_column_text(stmt, 5);
        
        // 创建日志对象
        cJSON *log = cJSON_CreateObject();
        if (log) {
            cJSON_AddNumberToObject(log, "log_id", log_id);
            cJSON_AddStringToObject(log, "op_time", (const char*)op_time);
            cJSON_AddStringToObject(log, "op_type", (const char*)op_type);
            cJSON_AddStringToObject(log, "file_name", file_name ? (const char*)file_name : "");
            cJSON_AddStringToObject(log, "ip", ip ? (const char*)ip : "");
            cJSON_AddStringToObject(log, "username", username ? (const char*)username : "");
            
            // 添加到数组
            cJSON_AddItemToArray(root, log);
        } else {
            fprintf(stderr, "Failed to create log JSON object\n");
            // 继续处理其他日志
        }
    }
    
    fprintf(stderr, "Found %d logs for user_id=%d\n", found_logs, user_id);
    
    // 清理语句
    sqlite3_finalize(stmt);
    
    // 转换为JSON字符串
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        fprintf(stderr, "Failed to print JSON\n");
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    fprintf(stderr, "Logs JSON: %s\n", json_str);
    
    // 发送响应头
    fprintf(stderr, "Sending logs response header [%02x %02x]\n", (unsigned char)header[0], (unsigned char)header[1]);
    if (send(client_fd, header, 2, 0) != 2) {
        fprintf(stderr, "Failed to send logs response header\n");
        free(json_str);
        sqlite3_close(db);
        return -1;
    }
    
    // 发送JSON数据
    size_t json_len = strlen(json_str);
    fprintf(stderr, "Sending logs data: %zu bytes\n", json_len);
    
    // 如果是空数组，则发送空数组字符串 "[]"
    if (found_logs == 0) {
        const char *empty_array = "[]";
        json_len = 2;
        
        ssize_t n = send(client_fd, empty_array, json_len, 0);
        if (n <= 0) {
            fprintf(stderr, "Failed to send empty logs list: %s\n", strerror(errno));
            free(json_str);
            sqlite3_close(db);
            return -1;
        }
    } else {
        ssize_t sent = 0;
        while (sent < json_len) {
            ssize_t n = send(client_fd, json_str + sent, json_len - sent, 0);
            if (n <= 0) {
                if (errno == EINTR) continue; // 被信号中断，重试
                fprintf(stderr, "Failed to send logs data: %s\n", strerror(errno));
                free(json_str);
                sqlite3_close(db);
                return -1;
            }
            sent += n;
        }
    }
    
    fprintf(stderr, "Logs data sent successfully\n");
    
    // 记录操作
    fprintf(stderr, "Sent logs to user %d\n", user_id);
    
    // 清理
    free(json_str);
    sqlite3_close(db);
    
    return 0;
}

// 处理密码修改请求
int handle_change_password(int client_fd, int user_id) {
    // 接收用户名
    char username[64] = {0};
    int i = 0;
    while (i < 63) {
        if (recv(client_fd, &username[i], 1, 0) != 1) break;
        if (username[i] == 0) break;
        i++;
    }
    
    // 接收旧密码
    char old_password[64] = {0};
    i = 0;
    while (i < 63) {
        if (recv(client_fd, &old_password[i], 1, 0) != 1) break;
        if (old_password[i] == 0) break;
        i++;
    }
    
    // 接收新密码
    char new_password[64] = {0};
    i = 0;
    while (i < 63) {
        if (recv(client_fd, &new_password[i], 1, 0) != 1) break;
        if (new_password[i] == 0) break;
        i++;
    }
    
    fprintf(stderr, "Password change request for user: %s\n", username);
    
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    
    rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 获取请求修改密码的用户ID和盐值
    const char *sql = "SELECT user_id, salt FROM users WHERE username = ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int target_user_id = -1;
    char salt[SALT_LEN + 1] = {0};
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        target_user_id = sqlite3_column_int(stmt, 0);
        const char* salt_text = (const char*)sqlite3_column_text(stmt, 1);
        if (salt_text) {
            strncpy(salt, salt_text, SALT_LEN);
            salt[SALT_LEN] = '\0';
        }
    }
    
    sqlite3_finalize(stmt);
    
    // 检查权限：用户只能修改自己的密码，管理员可以修改任何人的密码
    bool is_admin = false;
    if (user_id == 1) {  // 假设用户ID为1是管理员
        is_admin = true;
    }
    
    if (target_user_id == -1 || (target_user_id != user_id && !is_admin)) {
        fprintf(stderr, "Permission denied for changing password\n");
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 对旧密码进行哈希处理
    char old_password_hash[HASH_LEN] = {0};
    hash_password(old_password, salt, old_password_hash);
    
    // 验证旧密码
    const char *verify_sql = "SELECT 1 FROM users WHERE user_id = ? AND password_hash = ?;";
    rc = sqlite3_prepare_v2(db, verify_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, target_user_id);
    sqlite3_bind_text(stmt, 2, old_password_hash, -1, SQLITE_STATIC);
    
    bool password_correct = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        password_correct = true;
    }
    
    sqlite3_finalize(stmt);
    
    if (!password_correct) {
        fprintf(stderr, "Incorrect old password\n");
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 对新密码进行哈希处理
    char new_password_hash[HASH_LEN] = {0};
    hash_password(new_password, salt, new_password_hash);
    
    // 更新密码
    const char *update_sql = "UPDATE users SET password_hash = ? WHERE user_id = ?;";
    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, new_password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, target_user_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update password: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 记录密码修改操作
    // 获取客户端IP地址
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(client_fd, (struct sockaddr *)&addr, &addr_size);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    // 添加日志记录
    log_operation("密码修改", "", client_ip, user_id);
    
    // 发送成功响应
    char resp[2] = {MSG_RESULT, 1};
    send(client_fd, resp, 2, 0);
    
    sqlite3_close(db);
    return 0;
}

// 处理文件删除请求
int handle_delete_file(int client_fd, int user_id) {
    // 接收文件名
    char filename[256] = {0};
    int i = 0;
    while (i < 255) {
        if (recv(client_fd, &filename[i], 1, 0) != 1) break;
        if (filename[i] == 0) break;
        i++;
    }
    
    fprintf(stderr, "Delete request for file: %s from UID=%d\n", filename, user_id);
    
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    
    rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 检查文件是否存在及用户是否有权限删除
    const char *sql = "SELECT file_id, path, user_id FROM Files WHERE filename = ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
    
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        fprintf(stderr, "File not found: %s\n", filename);
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    int file_id = sqlite3_column_int(stmt, 0);
    const char *file_path = (const char *)sqlite3_column_text(stmt, 1);
    int file_owner = sqlite3_column_int(stmt, 2);
    
    // 只有文件所有者或管理员才能删除文件
    if (file_owner != user_id && user_id != 1) {
        fprintf(stderr, "Permission denied for deleting file\n");
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_finalize(stmt);
    
    // 删除物理文件
    if (remove(file_path) != 0) {
        fprintf(stderr, "Failed to delete file: %s\n", file_path);
        // 即使物理文件删除失败，我们仍然从数据库中删除记录
    }
    
    // 从数据库中删除文件记录
    const char *delete_sql = "DELETE FROM Files WHERE file_id = ?;";
    rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare delete statement: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, file_id);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to delete file record: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 获取客户端IP地址
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(client_fd, (struct sockaddr *)&addr, &addr_size);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    // 添加日志记录
    log_operation("删除", filename, client_ip, user_id);
    
    // 发送成功响应
    char resp[2] = {MSG_RESULT, 1};
    send(client_fd, resp, 2, 0);
    
    fprintf(stderr, "File deleted successfully: %s\n", filename);
    
    sqlite3_close(db);
    return 0;
}

// 处理文件搜索请求
int handle_search_files(int client_fd, int user_id) {
    // 接收搜索关键词
    char keyword[256] = {0};
    int i = 0;
    while (i < 255) {
        if (recv(client_fd, &keyword[i], 1, 0) != 1) break;
        if (keyword[i] == 0) break;
        i++;
    }
    
    fprintf(stderr, "Search request with keyword: %s from UID=%d\n", keyword, user_id);
    
    char header[2] = {MSG_LIST_FILES_RESP, 1}; // 使用与列表文件相同的响应格式
    
    // 查询数据库
    sqlite3 *db;
    sqlite3_stmt *stmt;
    
    int rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 准备搜索查询 - 使用LIKE进行模糊匹配
    const char *sql = "SELECT filename, upload_time, access_level FROM Files "
                     "WHERE (filename LIKE ? OR path LIKE ?) AND (user_id = ? OR access_level = 'public') "
                     "ORDER BY upload_time DESC";
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 构建搜索模式
    char search_pattern[300];
    snprintf(search_pattern, sizeof(search_pattern), "%%%s%%", keyword); // %keyword%
    
    // 绑定参数
    sqlite3_bind_text(stmt, 1, search_pattern, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, search_pattern, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, user_id);
    
    // 构建JSON数组
    cJSON *root = cJSON_CreateArray();
    
    // 执行查询并处理结果
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *filename = sqlite3_column_text(stmt, 0);
        const unsigned char *upload_time = sqlite3_column_text(stmt, 1);
        const unsigned char *access_level = sqlite3_column_text(stmt, 2);
        
        // 创建文件对象
        cJSON *file = cJSON_CreateObject();
        cJSON_AddStringToObject(file, "filename", (const char*)filename);
        cJSON_AddStringToObject(file, "upload_time", (const char*)upload_time);
        cJSON_AddStringToObject(file, "access_level", (const char*)access_level);
        
        // 添加到数组
        cJSON_AddItemToArray(root, file);
    }
    
    // 清理语句
    sqlite3_finalize(stmt);
    
    // 转换为JSON字符串
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    
    // 发送响应头
    if (send(client_fd, header, 2, 0) != 2) {
        fprintf(stderr, "Failed to send search response header\n");
        free(json_str);
        sqlite3_close(db);
        return -1;
    }
    
    // 发送JSON数据
    size_t json_len = strlen(json_str);
    ssize_t sent = 0;
    while (sent < json_len) {
        ssize_t n = send(client_fd, json_str + sent, json_len - sent, 0);
        if (n <= 0) {
            if (errno == EINTR) continue; // 被信号中断，重试
            fprintf(stderr, "Failed to send search data: %s\n", strerror(errno));
            free(json_str);
            sqlite3_close(db);
            return -1;
        }
        sent += n;
    }
    
    // 记录搜索操作
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(client_fd, (struct sockaddr *)&addr, &addr_size);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    log_operation("搜索", keyword, client_ip, user_id);
    
    // 清理
    free(json_str);
    sqlite3_close(db);
    
    return 0;
}

// 处理用户管理请求
int handle_user_manage(int client_fd, int user_id) {
    // 只有管理员可以访问用户管理功能
    if (user_id != 1) {
        fprintf(stderr, "User management access denied for non-admin user ID: %d\n", user_id);
        char header[2] = {MSG_USER_MANAGE, 0}; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 接收子命令
    char subcmd;
    if (recv(client_fd, &subcmd, 1, 0) != 1) {
        fprintf(stderr, "Failed to receive user management subcommand\n");
        char header[2] = {MSG_USER_MANAGE, 0};
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    if (subcmd == 0) {
        // 获取用户列表
        return handle_get_user_list(client_fd);
    } else if (subcmd == 1) {
        // 修改用户角色
        return handle_change_user_role(client_fd);
    } else {
        fprintf(stderr, "Unknown user management subcommand: %d\n", subcmd);
        char header[2] = {MSG_USER_MANAGE, 0};
        send(client_fd, header, 2, 0);
        return -1;
    }
}

// 处理获取用户列表请求
int handle_get_user_list(int client_fd) {
    char header[2] = {MSG_USER_MANAGE, 1}; // 1表示成功
    
    // 查询数据库
    sqlite3 *db;
    sqlite3_stmt *stmt;
    
    int rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 查询所有用户
    const char *sql = "SELECT user_id, username, register_time, role FROM users ORDER BY user_id";
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        header[1] = 0; // 0表示失败
        send(client_fd, header, 2, 0);
        return -1;
    }
    
    // 构建JSON数组
    cJSON *root = cJSON_CreateArray();
    
    // 执行查询并处理结果
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int user_id = sqlite3_column_int(stmt, 0);
        const unsigned char *username = sqlite3_column_text(stmt, 1);
        const unsigned char *register_time = sqlite3_column_text(stmt, 2);
        const unsigned char *role = sqlite3_column_text(stmt, 3);
        
        // 创建用户对象
        cJSON *user = cJSON_CreateObject();
        cJSON_AddNumberToObject(user, "user_id", user_id);
        cJSON_AddStringToObject(user, "username", (const char*)username);
        cJSON_AddStringToObject(user, "register_time", (const char*)register_time);
        cJSON_AddStringToObject(user, "role", (const char*)role ? (const char*)role : "user");
        
        // 添加到数组
        cJSON_AddItemToArray(root, user);
    }
    
    // 清理语句
    sqlite3_finalize(stmt);
    
    // 转换为JSON字符串
    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);
    
    // 发送响应头
    if (send(client_fd, header, 2, 0) != 2) {
        fprintf(stderr, "Failed to send user list response header\n");
        free(json_str);
        sqlite3_close(db);
        return -1;
    }
    
    // 发送JSON数据
    size_t json_len = strlen(json_str);
    ssize_t sent = 0;
    while (sent < json_len) {
        ssize_t n = send(client_fd, json_str + sent, json_len - sent, 0);
        if (n <= 0) {
            if (errno == EINTR) continue; // 被信号中断，重试
            fprintf(stderr, "Failed to send user list data: %s\n", strerror(errno));
            free(json_str);
            sqlite3_close(db);
            return -1;
        }
        sent += n;
    }
    
    // 清理
    free(json_str);
    sqlite3_close(db);
    
    return 0;
}

// 处理修改用户角色请求
int handle_change_user_role(int client_fd) {
    // 接收用户名
    char username[64] = {0};
    int i = 0;
    while (i < 63) {
        if (recv(client_fd, &username[i], 1, 0) != 1) break;
        if (username[i] == 0) break;
        i++;
    }
    
    // 接收新角色
    char new_role[32] = {0};
    i = 0;
    while (i < 31) {
        if (recv(client_fd, &new_role[i], 1, 0) != 1) break;
        if (new_role[i] == 0) break;
        i++;
    }
    
    fprintf(stderr, "Change role request for user: %s to %s\n", username, new_role);
    
    // 验证角色是否有效
    if (strcmp(new_role, "user") != 0 && strcmp(new_role, "admin") != 0) {
        fprintf(stderr, "Invalid role: %s\n", new_role);
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        return -1;
    }
    
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    
    rc = sqlite3_open("secure_file_transfer.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 更新用户角色
    const char *sql = "UPDATE users SET role = ? WHERE username = ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, new_role, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Failed to update user role: %s\n", sqlite3_errmsg(db));
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 检查是否有更新
    if (sqlite3_changes(db) == 0) {
        fprintf(stderr, "No user found with username: %s\n", username);
        char resp[2] = {MSG_RESULT, 0};
        send(client_fd, resp, 2, 0);
        sqlite3_close(db);
        return -1;
    }
    
    // 获取客户端IP地址
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(client_fd, (struct sockaddr *)&addr, &addr_size);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    // 添加日志记录
    log_operation("角色修改", username, client_ip, 1); // 1表示管理员用户ID
    
    // 发送成功响应
    char resp[2] = {MSG_RESULT, 1};
    send(client_fd, resp, 2, 0);
    
    fprintf(stderr, "User role updated successfully: %s -> %s\n", username, new_role);
    
    sqlite3_close(db);
    return 0;
}

void handle_client(int client_fd) {
    int user_id = 0;  // 0表示未登录
    
    // 设置非阻塞模式
#ifdef _WIN32
    u_long mode = 1;  // 1 = 非阻塞
    ioctlsocket(client_fd, FIONBIO, &mode);
#else
    int flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
#endif

    // 设置TCP_NODELAY选项，减少延迟
    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
    
    // 获取客户端IP地址
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(client_fd, (struct sockaddr *)&addr, &addr_size);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    fprintf(stderr, "Client %s connected\n", client_ip);
    
    while (1) {
        // 使用select等待数据
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        
        struct timeval tv;
        tv.tv_sec = 60;  // 60秒超时
        tv.tv_usec = 0;
        
        int select_result = select(client_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (select_result < 0) {
            fprintf(stderr, "Select error: %s\n", strerror(errno));
            break;
        } else if (select_result == 0) {
            fprintf(stderr, "Client connection timed out\n");
            break;
        }
        
        // 接收命令
        char cmd;
        int n = recv(client_fd, &cmd, 1, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // 暂时没有数据，继续等待
                continue;
            }
            
            if (n < 0) {
                fprintf(stderr, "Receive error: %s\n", strerror(errno));
            } else {
                fprintf(stderr, "Connection closed\n");
            }
            break;
        }
        
        fprintf(stderr, "Received command: %02x, length: %d\n", (unsigned char)cmd, n);
        
        // 处理不同的命令
        switch (cmd) {
            case MSG_LOGIN: {
                // 接收用户名和密码
                char username[64] = {0};
                char password[64] = {0};
                int i = 0;
                
                // 接收用户名
                while (i < 63) {
                    if (recv(client_fd, &username[i], 1, 0) != 1) break;
                    if (username[i] == 0) break;
                    i++;
                }
                
                // 接收密码
                i = 0;
                while (i < 63) {
                    if (recv(client_fd, &password[i], 1, 0) != 1) break;
                    if (password[i] == 0) break;
                    i++;
                }
                
                fprintf(stderr, "Login attempt: %s\n", username);
                
                // 验证用户名和密码(连接到数据库验证)
                sqlite3 *db;
                sqlite3_stmt *stmt;
                int rc;
                bool login_success = false;
                
                rc = sqlite3_open("secure_file_transfer.db", &db);
                if (rc != SQLITE_OK) {
                    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
                    char resp[2] = {MSG_RESULT, 0};  // 0表示失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                // 首先获取用户的盐值
                const char *salt_sql = "SELECT user_id, salt FROM users WHERE username = ?;";
                rc = sqlite3_prepare_v2(db, salt_sql, -1, &stmt, NULL);
                if (rc != SQLITE_OK) {
                    fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    char resp[2] = {MSG_RESULT, 0};  // 0表示失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                
                int found_user_id = -1;
                char salt[SALT_LEN + 1] = {0};
                
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    found_user_id = sqlite3_column_int(stmt, 0);
                    const char* salt_text = (const char*)sqlite3_column_text(stmt, 1);
                    if (salt_text) {
                        strncpy(salt, salt_text, SALT_LEN);
                        salt[SALT_LEN] = '\0';
                    }
                }
                
                sqlite3_finalize(stmt);
                
                if (found_user_id <= 0 || strlen(salt) == 0) {
                    // 用户不存在或盐值获取失败
                    char resp[2] = {MSG_RESULT, 0};  // 0表示失败
                    send(client_fd, resp, 2, 0);
                    sqlite3_close(db);
                    fprintf(stderr, "User not found or salt retrieval failed\n");
                    continue;
                }
                
                // 计算密码哈希
                char password_hash[HASH_LEN] = {0};
                hash_password(password, salt, password_hash);
                
                // 验证密码哈希
                const char *verify_sql = "SELECT user_id FROM users WHERE username = ? AND password_hash = ?;";
                rc = sqlite3_prepare_v2(db, verify_sql, -1, &stmt, NULL);
                if (rc != SQLITE_OK) {
                    fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
                    sqlite3_close(db);
                    char resp[2] = {MSG_RESULT, 0};  // 0表示失败
                    send(client_fd, resp, 2, 0);
                    continue;
                }
                
                sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);
                
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    user_id = sqlite3_column_int(stmt, 0);
                    login_success = true;
                    
                    // 发送成功响应
                    char resp[2] = {MSG_RESULT, 1};  // 1表示成功
                    send(client_fd, resp, 2, 0);
                    
                    fprintf(stderr, "[LOGIN] User '%s' login success.\n", username);
                    fprintf(stderr, "[SERVER] User '%s' logged in as UID=%d\n", username, user_id);
                } else {
                    // 发送失败响应
                    char resp[2] = {MSG_RESULT, 0};  // 0表示失败
                    send(client_fd, resp, 2, 0);
                    
                    fprintf(stderr, "[LOGIN] User '%s' login failed.\n", username);
                }
                
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                break;
            }
                
            case MSG_UPLOAD:
                // 处理上传请求
                if (user_id > 0) {
                    handle_upload(client_fd, user_id);
                } else {
                    // 用户未登录，发送错误响应
                    fprintf(stderr, "Upload request rejected: user not logged in\n");
                }
                break;
                
            case MSG_DOWNLOAD:
                // 处理下载请求
                if (user_id > 0) {
                    // 实现下载处理函数
                } else {
                    // 用户未登录，发送错误响应
                    fprintf(stderr, "Download request rejected: user not logged in\n");
                }
                break;
                
            case MSG_LIST_FILES:
                // 处理获取文件列表请求
                fprintf(stderr, "Handling file list request\n");
                if (user_id > 0) {
                    handle_list_files(client_fd, user_id);
                } else {
                    // 用户未登录，发送错误响应
                    char header[2] = {MSG_LIST_FILES_RESP, 0}; // 0表示失败
                    send(client_fd, header, 2, 0);
                    fprintf(stderr, "User not logged in, cannot list files\n");
                }
                break;
                
            case MSG_GET_LOGS:
                // 处理获取日志请求
                fprintf(stderr, "Handling logs request\n");
                if (user_id > 0) {
                    handle_get_logs(client_fd, user_id);
                } else {
                    // 用户未登录，发送错误响应
                    char header[2] = {MSG_LOGS_RESP, 0}; // 0表示失败
                    send(client_fd, header, 2, 0);
                    fprintf(stderr, "User not logged in, cannot get logs\n");
                }
                break;
                
            case MSG_CHANGE_PASS:
                // 处理密码修改请求
                if (user_id > 0) {
                    handle_change_password(client_fd, user_id);
                } else {
                    // 用户未登录，发送错误响应
                    char resp[2] = {MSG_RESULT, 0};
                    send(client_fd, resp, 2, 0);
                    fprintf(stderr, "Password change request rejected: user not logged in\n");
                }
                break;
                
            case MSG_DELETE_FILE:
                // 处理文件删除请求
                if (user_id > 0) {
                    handle_delete_file(client_fd, user_id);
                } else {
                    // 用户未登录，发送错误响应
                    char resp[2] = {MSG_RESULT, 0};
                    send(client_fd, resp, 2, 0);
                    fprintf(stderr, "File deletion request rejected: user not logged in\n");
                }
                break;
                
            case MSG_SEARCH_FILES:
                // 处理文件搜索请求
                if (user_id > 0) {
                    handle_search_files(client_fd, user_id);
                } else {
                    // 用户未登录，发送错误响应
                    char header[2] = {MSG_LIST_FILES_RESP, 0};
                    send(client_fd, header, 2, 0);
                    fprintf(stderr, "File search request rejected: user not logged in\n");
                }
                break;
                
            case MSG_USER_MANAGE:
                // 处理用户管理请求
                if (user_id > 0) {
                    handle_user_manage(client_fd, user_id);
                } else {
                    // 用户未登录，发送错误响应
                    char header[2] = {MSG_USER_MANAGE, 0};
                    send(client_fd, header, 2, 0);
                    fprintf(stderr, "User management request rejected: user not logged in\n");
                }
                break;
                
            default:
                fprintf(stderr, "Unknown command: %02x\n", (unsigned char)cmd);
                break;
        }
    }
    
    fprintf(stderr, "Connection closed\n");
    close(client_fd);
}

// 初始化数据库
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
                           "id INTEGER PRIMARY KEY AUTOINCREMENT,"
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
                           "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                           "filename TEXT NOT NULL,"
                           "path TEXT NOT NULL,"
                           "owner INTEGER NOT NULL,"
                           "access_level TEXT DEFAULT 'private',"
                           "upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,"
                           "FOREIGN KEY (owner) REFERENCES users(id)"
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
                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "op_time DATETIME DEFAULT CURRENT_TIMESTAMP,"
                          "op_type TEXT NOT NULL,"
                          "file_name TEXT,"
                          "ip TEXT,"
                          "user_id INTEGER,"
                          "FOREIGN KEY (user_id) REFERENCES users(id)"
                          ");";
    
    rc = sqlite3_exec(db, sql_logs, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
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

// 修改main函数，在服务器启动时初始化数据库
int main(int argc, char *argv[]) {
    // 初始化数据库
    if (init_database() != 0) {
        fprintf(stderr, "Failed to initialize database\n");
        return 1;
    }
    
    // ... existing code ...
} 