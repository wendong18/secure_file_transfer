#include <stdio.h>
#include <string.h>
#include "../include/common.h"
#include "../include/db_init.h"

extern int register_user(const char*, const char*);
extern int login_user(const char*, const char*);

int main() {
    // 初始化数据库
    if (init_database() != 0) {
        fprintf(stderr, "数据库初始化失败\n");
        return 1;
    }
    
    printf("数据库初始化成功\n");
    printf("系统已预设管理员账号：admin/admin123\n\n");

    UserInfo user;

    printf("请输入注册用户名: ");
    scanf("%s", user.username);
    printf("请输入密码: ");
    scanf("%s", user.password);

    int reg_result = register_user(user.username, user.password);
    if (reg_result == 0) {
        printf("注册成功\n");
    } else if (reg_result == -2) {
        printf("注册失败：用户名已存在\n");
    } else if (reg_result == -3) {
        printf("注册失败：不能使用保留的用户名 'admin'\n");
        printf("请使用系统预设的管理员账号：admin/admin123\n");
    } else {
        printf("注册失败：错误代码 %d\n", reg_result);
    }

    printf("请输入登录用户名: ");
    scanf("%s", user.username);
    printf("请输入密码: ");
    scanf("%s", user.password);

    int login_result = login_user(user.username, user.password);
    if (login_result) {
        printf("登录成功\n");
    } else {
        printf("登录失败\n");
    }

    return 0;
}
