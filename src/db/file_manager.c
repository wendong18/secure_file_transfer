#include "../../include/file_manager.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../include/user_auth.h"

static sqlite3* open_db(void) {
    sqlite3* db;
    if (sqlite3_open("secure_file_transfer.db", &db) != SQLITE_OK) return NULL;
    return db;
}

int add_file_record(const char* filename,
                    const char* filepath,
                    int owner_id,
                    const char* access_level) {
    fprintf(stderr, "Adding file record: filename=%s, path=%s, owner=%d, access=%s\n", 
            filename, filepath, owner_id, access_level);
            
    sqlite3* db = open_db();
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return -1;
    }
    
    // 检查文件记录是否已存在
    sqlite3_stmt* check_stmt = NULL;
    const char* check_sql = "SELECT file_id FROM files WHERE filename=? AND user_id=?;";
    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare check statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_bind_text(check_stmt, 1, filename, -1, NULL);
    sqlite3_bind_int(check_stmt, 2, owner_id);
    
    int file_exists = 0;
    int file_id = 0;
    if (sqlite3_step(check_stmt) == SQLITE_ROW) {
        file_exists = 1;
        file_id = sqlite3_column_int(check_stmt, 0);
        fprintf(stderr, "File already exists with ID %d, will update\n", file_id);
    }
    sqlite3_finalize(check_stmt);
    
    int rc = -1;
    if (file_exists) {
        // 更新现有记录
        const char* update_sql = 
            "UPDATE files SET file_path=?, access_level=?, upload_time=CURRENT_TIMESTAMP WHERE file_id=?;";
        sqlite3_stmt* update_stmt = NULL;
        
        if (sqlite3_prepare_v2(db, update_sql, -1, &update_stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare update statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return -1;
        }
        
        sqlite3_bind_text(update_stmt, 1, filepath, -1, NULL);
        sqlite3_bind_text(update_stmt, 2, access_level, -1, NULL);
        sqlite3_bind_int(update_stmt, 3, file_id);
        
        rc = (sqlite3_step(update_stmt) == SQLITE_DONE) ? 0 : -1;
        if (rc != 0) {
            fprintf(stderr, "Failed to update file record: %s\n", sqlite3_errmsg(db));
        } else {
            fprintf(stderr, "File record updated successfully\n");
        }
        
        sqlite3_finalize(update_stmt);
    } else {
        // 插入新记录
        const char* sql =
          "INSERT INTO files(filename,file_path,access_level,user_id) VALUES(?,?,?,?);";
        sqlite3_stmt* stmt = NULL;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            return -1;
        }
        
        sqlite3_bind_text(stmt, 1, filename, -1, NULL);
        sqlite3_bind_text(stmt, 2, filepath, -1, NULL);
        sqlite3_bind_text(stmt, 3, access_level, -1, NULL);
        sqlite3_bind_int(stmt, 4, owner_id);
        
        rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
        if (rc != 0) {
            fprintf(stderr, "Failed to insert file record: %s\n", sqlite3_errmsg(db));
        } else {
            fprintf(stderr, "File record inserted successfully with ID %lld\n", 
                    (long long)sqlite3_last_insert_rowid(db));
        }
        
        sqlite3_finalize(stmt);
    }
    
    sqlite3_close(db);
    return rc;
}

int check_file_permission(int file_id, int user_id) {
    sqlite3* db = open_db();
    if (!db) return 0;
    const char* sql = "SELECT access_level,user_id FROM files WHERE file_id=?;";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)!=SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }
    sqlite3_bind_int(stmt, 1, file_id);
    int allowed = 0;
    if (sqlite3_step(stmt)==SQLITE_ROW) {
        const char* access = (char*)sqlite3_column_text(stmt,0);
        int owner = sqlite3_column_int(stmt,1);
        if (is_admin(user_id)) {
            allowed = 1;
        } else if (strcmp(access,"public")==0) {
            allowed = 1;
        } else if (strcmp(access,"private")==0 && owner==user_id) {
            allowed = 1;
        } else if (strcmp(access,"admin-only")==0 && is_admin(user_id)) {
            allowed = 1;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return allowed;
}

int list_user_files(int user_id, char* result, int maxlen) {
    sqlite3* db = open_db();
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        strcpy(result, "[]");
        return 0;
    }
    
    fprintf(stderr, "Listing files for user_id=%d\n", user_id);
    
    // 检查数据库表结构
    int has_is_admin_column = 0;
    sqlite3_stmt* check_stmt = NULL;
    const char* check_sql = "PRAGMA table_info(users);";
    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const char* column_name = (const char*)sqlite3_column_text(check_stmt, 1);
            if (column_name && strcmp(column_name, "is_admin") == 0) {
                has_is_admin_column = 1;
                break;
            }
        }
        sqlite3_finalize(check_stmt);
    }
    
    // 根据数据库结构选择查询方式
    const char* sql = NULL;
    if (has_is_admin_column) {
        sql = "SELECT f.file_id, f.filename, f.upload_time, f.access_level, f.user_id "
              "FROM files f "
              "WHERE f.user_id = ? OR f.access_level = 'public' OR "
              "(f.access_level = 'admin-only' AND (SELECT is_admin FROM users WHERE user_id = ?));";
    } else {
        sql = "SELECT f.file_id, f.filename, f.upload_time, f.access_level, f.user_id "
              "FROM files f "
              "LEFT JOIN users u ON u.user_id = ? "
              "WHERE f.user_id = ? OR f.access_level = 'public' OR "
              "(f.access_level = 'admin-only' AND (u.username LIKE '%admin%' OR ? = 1));";
    }
    
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare SQL statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        strcpy(result, "[]");
        return 0;
    }
    
    // 绑定参数
    if (has_is_admin_column) {
        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, user_id);
    } else {
        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, user_id);
        sqlite3_bind_int(stmt, 3, user_id == 1 ? 1 : 0); // 用户ID为1视为管理员
    }
    
    // 创建一个临时数组来存储有效的文件项
    struct FileItem {
        int file_id;
        char filename[256];
        char upload_time[64];
        char access_level[32];
    };
    
    struct FileItem* files = malloc(100 * sizeof(struct FileItem)); // 假设最多100个文件
    if (!files) {
        fprintf(stderr, "Failed to allocate memory for file items\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        strcpy(result, "[]");
        return 0;
    }
    
    int count = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW && count < 100) {
        int file_id = sqlite3_column_int(stmt, 0);
        const char* filename = (const char*)sqlite3_column_text(stmt, 1);
        const char* upload_time = (const char*)sqlite3_column_text(stmt, 2);
        const char* access_level = (const char*)sqlite3_column_text(stmt, 3);
        int owner_id = sqlite3_column_int(stmt, 4);
        
        if (!filename) filename = "";
        if (!upload_time) upload_time = "";
        if (!access_level) access_level = "private"; // 默认为private
        
        // 检查权限 - 跳过不应该显示的文件
        if (strcmp(access_level, "private") == 0 && owner_id != user_id) {
            continue; // 跳过其他用户的私有文件
        }
        
        // 检查是否为管理员用户
        int is_admin_user = is_admin(user_id);
        if (strcmp(access_level, "admin-only") == 0 && !is_admin_user) {
            continue; // 跳过管理员专用文件（如果用户不是管理员）
        }
        
        fprintf(stderr, "Adding file to result: id=%d, name=%s, access=%s\n", 
                file_id, filename, access_level);
        
        // 存储文件信息到临时数组
        files[count].file_id = file_id;
        strncpy(files[count].filename, filename, sizeof(files[count].filename)-1);
        files[count].filename[sizeof(files[count].filename)-1] = '\0';
        
        strncpy(files[count].upload_time, upload_time, sizeof(files[count].upload_time)-1);
        files[count].upload_time[sizeof(files[count].upload_time)-1] = '\0';
        
        strncpy(files[count].access_level, access_level, sizeof(files[count].access_level)-1);
        files[count].access_level[sizeof(files[count].access_level)-1] = '\0';
        
        count++;
    }
    
    // 构建JSON数组
    int offset = 0;
    offset += snprintf(result+offset, maxlen-offset, "[");
    
    for (int i = 0; i < count; i++) {
        // 添加逗号，除了第一个元素
        if (i > 0) {
            offset += snprintf(result+offset, maxlen-offset, ",");
        }
        
        // 添加文件信息
        offset += snprintf(result+offset, maxlen-offset,
            "{\"file_id\":%d,\"filename\":\"%s\",\"upload_time\":\"%s\",\"access_level\":\"%s\"}",
            files[i].file_id, files[i].filename, files[i].upload_time, files[i].access_level);
        
        // 检查是否接近缓冲区限制
        if (offset >= maxlen-128) {
            fprintf(stderr, "Warning: Buffer limit reached, truncating results\n");
            break;
        }
    }
    
    // 关闭JSON数组
    offset += snprintf(result+offset, maxlen-offset, "]");
    
    // 释放临时数组
    free(files);
    
    // 清理资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    fprintf(stderr, "Found %d files for user_id=%d, result: %s\n", count, user_id, result);
    return count;
}

int add_log(int user_id, const char* username, const char* op_type, const char* file_name, const char* ip) {
    fprintf(stderr, "[DEBUG] add_log: Adding log for user_id=%d, username=%s, op_type=%s\n", 
            user_id, username ? username : "NULL", op_type ? op_type : "NULL");
    
    sqlite3* db = open_db();
    if (!db) {
        fprintf(stderr, "[ERROR] add_log: Failed to open database\n");
        return -1;
    }
    
    // 首先检查logs表的结构
    sqlite3_stmt* check_stmt = NULL;
    const char* check_sql = "PRAGMA table_info(logs);";
    int has_username_column = 0;
    
    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const char* column_name = (const char*)sqlite3_column_text(check_stmt, 1);
            if (column_name && strcmp(column_name, "username") == 0) {
                has_username_column = 1;
                break;
            }
        }
        sqlite3_finalize(check_stmt);
    }
    
    fprintf(stderr, "[DEBUG] add_log: Table has username column: %s\n", has_username_column ? "yes" : "no");
    
    // 根据表结构选择SQL语句
    const char* sql = NULL;
    if (has_username_column) {
        sql = "INSERT INTO logs(user_id,username,op_type,file_name,ip) VALUES(?,?,?,?,?);";
    } else {
        // 没有username列，使用不包含username的插入语句
        sql = "INSERT INTO logs(user_id,op_type,file_name,ip) VALUES(?,?,?,?);";
    }
    
    fprintf(stderr, "[DEBUG] add_log: Using SQL: %s\n", sql);
    
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[ERROR] add_log: Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    sqlite3_bind_int(stmt, 1, user_id);
    
    if (has_username_column) {
        sqlite3_bind_text(stmt, 2, username ? username : "", -1, NULL);
        sqlite3_bind_text(stmt, 3, op_type ? op_type : "", -1, NULL);
        sqlite3_bind_text(stmt, 4, file_name ? file_name : "", -1, NULL);
        sqlite3_bind_text(stmt, 5, ip ? ip : "", -1, NULL);
    } else {
        sqlite3_bind_text(stmt, 2, op_type ? op_type : "", -1, NULL);
        sqlite3_bind_text(stmt, 3, file_name ? file_name : "", -1, NULL);
        sqlite3_bind_text(stmt, 4, ip ? ip : "", -1, NULL);
    }
    
    // 执行插入
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    
    if (rc != 0) {
        fprintf(stderr, "[ERROR] add_log: Failed to insert log: %s\n", sqlite3_errmsg(db));
    } else {
        fprintf(stderr, "[DEBUG] add_log: Log added successfully\n");
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int list_logs(int user_id, int is_admin, char* result, int maxlen) {
    fprintf(stderr, "[DEBUG] list_logs: Starting for user_id=%d, is_admin=%d\n", user_id, is_admin);
    
    // 确保结果缓冲区初始化为空
    if (result && maxlen > 0) {
        result[0] = '\0';
    }
    
    sqlite3* db = open_db();
    if (!db) {
        fprintf(stderr, "[ERROR] list_logs: Failed to open database\n");
        if (result && maxlen >= 3) {
            strncpy(result, "[]", maxlen);
        }
        return -1;
    }
    
    // 首先检查logs表是否存在
    sqlite3_stmt* check_stmt = NULL;
    const char* check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='logs';";
    int table_exists = 0;
    
    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            table_exists = 1;
        }
        sqlite3_finalize(check_stmt);
    }
    
    if (!table_exists) {
        fprintf(stderr, "[ERROR] list_logs: logs表不存在，尝试创建\n");
        const char* create_sql = "CREATE TABLE IF NOT EXISTS logs ("
                                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                "op_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                                "op_type TEXT,"
                                "file_name TEXT,"
                                "ip TEXT,"
                                "user_id INTEGER);";
        
        if (sqlite3_exec(db, create_sql, NULL, NULL, NULL) != SQLITE_OK) {
            fprintf(stderr, "[ERROR] list_logs: 创建logs表失败: %s\n", sqlite3_errmsg(db));
            if (result && maxlen >= 3) {
                strncpy(result, "[]", maxlen);
            }
            sqlite3_close(db);
            return -1;
        }
        
        fprintf(stderr, "[INFO] list_logs: logs表已创建\n");
        if (result && maxlen >= 3) {
            strncpy(result, "[]", maxlen);
        }
        sqlite3_close(db);
        return 0;
    }
    
    // 检查logs表的结构
    check_sql = "PRAGMA table_info(logs);";
    check_stmt = NULL;
    int has_username_column = 0;
    
    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const char* column_name = (const char*)sqlite3_column_text(check_stmt, 1);
            if (column_name && strcmp(column_name, "username") == 0) {
                has_username_column = 1;
                break;
            }
        }
        sqlite3_finalize(check_stmt);
    }
    
    fprintf(stderr, "[DEBUG] list_logs: Table has username column: %s\n", has_username_column ? "yes" : "no");
    
    // 根据表结构选择SQL查询
    const char* sql_admin = NULL;
    const char* sql_user = NULL;
    
    if (has_username_column) {
        sql_admin = "SELECT log_id, op_time, op_type, file_name, ip, user_id, username FROM logs ORDER BY op_time DESC LIMIT 100;";
        sql_user = "SELECT log_id, op_time, op_type, file_name, ip, user_id, username FROM logs WHERE user_id=? ORDER BY op_time DESC LIMIT 100;";
    } else {
        sql_admin = "SELECT log_id, op_time, op_type, file_name, ip, user_id FROM logs ORDER BY op_time DESC LIMIT 100;";
        sql_user = "SELECT log_id, op_time, op_type, file_name, ip, user_id FROM logs WHERE user_id=? ORDER BY op_time DESC LIMIT 100;";
    }
    
    fprintf(stderr, "[DEBUG] list_logs: Using SQL query: %s\n", is_admin ? sql_admin : sql_user);
    
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, is_admin ? sql_admin : sql_user, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "[ERROR] list_logs: Failed to prepare query: %s\n", sqlite3_errmsg(db));
        if (result && maxlen >= 3) {
            strncpy(result, "[]", maxlen);
        }
        sqlite3_close(db);
        return -1;
    }
    
    if (!is_admin) {
        fprintf(stderr, "[DEBUG] list_logs: Binding user_id=%d to query\n", user_id);
        sqlite3_bind_int(stmt, 1, user_id);
    }
    
    int count = 0, offset = 0;
    
    // 确保有足够的空间
    if (maxlen < 3) {
        fprintf(stderr, "[ERROR] list_logs: Result buffer too small\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }
    
    offset += snprintf(result+offset, maxlen-offset, "[");
    
    while (sqlite3_step(stmt) == SQLITE_ROW && offset < maxlen-256) {
        if (count > 0) offset += snprintf(result+offset, maxlen-offset, ",");
        
        int log_id = sqlite3_column_int(stmt, 0);
        const char* op_time = (const char*)sqlite3_column_text(stmt, 1);
        const char* op_type = (const char*)sqlite3_column_text(stmt, 2);
        const char* file_name = (const char*)sqlite3_column_text(stmt, 3);
        const char* ip = (const char*)sqlite3_column_text(stmt, 4);
        int log_user_id = sqlite3_column_int(stmt, 5);
        const char* username = has_username_column ? (const char*)sqlite3_column_text(stmt, 6) : NULL;
        
        fprintf(stderr, "[DEBUG] list_logs: Processing log entry %d: user=%d, type=%s\n", 
                log_id, log_user_id, op_type ? op_type : "NULL");
        
        // 获取用户名（如果表中没有）
        char username_buf[64] = {0};
        if (!username) {
            char* result_name = get_username_by_id(log_user_id, username_buf, sizeof(username_buf));
            if (result_name) {
                username = username_buf;
            } else {
                // 如果无法获取用户名，使用用户ID作为备用
                snprintf(username_buf, sizeof(username_buf), "UID:%d", log_user_id);
                username = username_buf;
            }
        }
        
        // 安全处理NULL值
        if (!op_time) op_time = "";
        if (!op_type) op_type = "";
        if (!file_name) file_name = "";
        if (!ip) ip = "";
        if (!username) username = "";
        
        // 构建JSON对象
        offset += snprintf(result+offset, maxlen-offset,
            "{\"log_id\":%d,\"op_time\":\"%s\",\"op_type\":\"%s\",\"file_name\":\"%s\",\"ip\":\"%s\",\"user_id\":%d,\"username\":\"%s\"}",
            log_id, op_time, op_type, file_name, ip, log_user_id, username);
        
        count++;
        if (offset >= maxlen-256) {
            fprintf(stderr, "[WARNING] list_logs: Results truncated due to buffer size\n");
            break;
        }
    }
    
    // 确保JSON数组正确关闭
    offset += snprintf(result+offset, maxlen-offset, "]");
    result[maxlen-1] = '\0'; // 确保字符串正确终止
    
    fprintf(stderr, "[DEBUG] list_logs: Finished with %d entries, JSON size=%d bytes\n", count, offset);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

int delete_file_record(int file_id) {
    sqlite3* db = open_db();
    if (!db) {
        fprintf(stderr, "Failed to open database\n");
        return -1;
    }
    
    // 准备SQL语句
    const char* sql = "DELETE FROM files WHERE file_id=?;";
    sqlite3_stmt* stmt = NULL;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare delete statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }
    
    // 绑定参数
    sqlite3_bind_int(stmt, 1, file_id);
    
    // 执行删除
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    
    if (rc != 0) {
        fprintf(stderr, "Failed to delete file record: %s\n", sqlite3_errmsg(db));
    } else {
        fprintf(stderr, "File record with ID %d deleted successfully\n", file_id);
    }
    
    // 清理资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return rc;
}
