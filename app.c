#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <ctype.h>
#include "include/common.h"
#include "include/user_auth.h"
#include "include/db_init.h"

/**
 * 显示主菜单
 */
void print_menu() {
    printf("\n=== 安全文件传输系统 ===\n");
    printf("1. 注册新用户\n");
    printf("2. 用户登录\n");
    printf("0. 退出程序\n");
    printf("请选择操作: ");
}

/**
 * 清除输入缓冲区
 */
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

/**
 * 安全读取字符串，防止缓冲区溢出
 * @param buffer 存储读取内容的缓冲区
 * @param size 缓冲区大小
 * @param prompt 提示信息
 * @return 成功返回1，失败返回0
 */
int safe_read_string(char* buffer, size_t size, const char* prompt) {
    if (!buffer || size < 2) return 0;
    
    printf("%s", prompt);
    
    if (fgets(buffer, size, stdin) == NULL) {
        return 0;
    }
    
    // 移除换行符
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len-1] == '\n') {
        buffer[len-1] = '\0';
    } else {
        // 输入太长，清除缓冲区
        clear_input_buffer();
    }
    
    return 1;
}

/**
 * 检查用户名是否有效（只包含字母、数字和下划线）
 * @param username 要检查的用户名
 * @return 有效返回1，无效返回0
 */
int is_valid_username(const char* username) {
    if (!username || strlen(username) < 3) return 0;
    
    for (size_t i = 0; username[i]; i++) {
        char c = username[i];
        if (!isalnum(c) && c != '_') {
            return 0;
        }
    }
    
    return 1;
}

/**
 * 检查密码强度
 * @param password 要检查的密码
 * @return 强度评分（0-10，分数越高越强）
 */
int check_password_strength(const char* password) {
    if (!password) return 0;
    
    int score = 0;
    int len = strlen(password);
    int has_lower = 0, has_upper = 0, has_digit = 0, has_special = 0;
    
    // 长度得分（最多5分）
    if (len >= 12) score += 5;
    else if (len >= 10) score += 4;
    else if (len >= 8) score += 3;
    else if (len >= 6) score += 2;
    else score += 1;
    
    // 检查字符类型
    for (int i = 0; i < len; i++) {
        if (islower(password[i])) has_lower = 1;
        else if (isupper(password[i])) has_upper = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else has_special = 1;
    }
    
    // 字符多样性得分（最多5分）
    score += has_lower + has_upper + has_digit + has_special + 
             (has_lower && has_upper && has_digit && has_special);
    
    return score;
}

/**
 * 安全的注册用户函数
 */
void safe_register_user() {
    char username[MAX_USERNAME_LEN] = {0};
    char password[MAX_PASSWORD_LEN] = {0};
    char confirm_password[MAX_PASSWORD_LEN] = {0};
    
    printf("\n=== 用户注册 ===\n");
    
    // 读取用户名
    if (!safe_read_string(username, sizeof(username), "请输入用户名(3-64字符，只能包含字母、数字和下划线): ")) {
        printf("读取用户名失败\n");
        return;
    }
    
    // 验证用户名
    if (!is_valid_username(username)) {
        printf("用户名无效，只能包含字母、数字和下划线，且长度至少为3个字符\n");
        return;
    }
    
    // 读取密码
    if (!safe_read_string(password, sizeof(password), "请输入密码(6-64字符): ")) {
        printf("读取密码失败\n");
        return;
    }
    
    // 验证密码长度
    if (strlen(password) < 6) {
        printf("密码长度必须至少为6个字符\n");
        return;
    }
    
    // 检查密码强度
    int strength = check_password_strength(password);
    printf("密码强度: ");
    if (strength >= 8) {
        printf("强\n");
    } else if (strength >= 5) {
        printf("中\n");
    } else {
        printf("弱（建议包含大小写字母、数字和特殊字符）\n");
    }
    
    // 确认密码
    if (!safe_read_string(confirm_password, sizeof(confirm_password), "请再次输入密码: ")) {
        printf("读取确认密码失败\n");
        return;
    }
    
    // 检查两次输入的密码是否一致
    if (strcmp(password, confirm_password) != 0) {
        printf("两次输入的密码不一致，注册失败\n");
        return;
    }
    
    // 调用注册函数
    int result = register_user(username, password);
    
    // 处理注册结果
    if (result == 0) {
        printf("注册成功！用户 %s 已创建\n", username);
    } else if (result == -2) {
        printf("用户名 %s 已存在，请选择其他用户名\n", username);
    } else {
        printf("注册失败，错误代码: %d\n", result);
    }
}

/**
 * 安全的登录函数
 */
void safe_login_user() {
    char username[MAX_USERNAME_LEN] = {0};
    char password[MAX_PASSWORD_LEN] = {0};
    
    printf("\n=== 用户登录 ===\n");
    
    // 读取用户名
    if (!safe_read_string(username, sizeof(username), "请输入用户名: ")) {
        printf("读取用户名失败\n");
        return;
    }
    
    // 读取密码
    if (!safe_read_string(password, sizeof(password), "请输入密码: ")) {
        printf("读取密码失败\n");
        return;
    }
    
    // 调用登录函数
    int result = login_user(username, password);
    
    // 处理登录结果
    if (result) {
        printf("登录成功！欢迎 %s\n", username);
        // 这里可以添加登录后的操作
    } else {
        printf("登录失败，用户名或密码错误\n");
    }
}

/**
 * 主函数
 */
int main() {
    // 初始化数据库
    printf("正在初始化数据库...\n");
    init_database();
    printf("数据库初始化完成\n");
    
    int choice = 0;
    
    do {
        print_menu();
        
        // 安全地读取用户选择
        if (scanf("%d", &choice) != 1) {
            printf("输入无效，请重试\n");
            // 清除输入缓冲区
            clear_input_buffer();
            choice = -1;
            continue;
        }
        
        // 清除输入缓冲区
        clear_input_buffer();
        
        switch (choice) {
            case 1:
                safe_register_user();
                break;
            case 2:
                safe_login_user();
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