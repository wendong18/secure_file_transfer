#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmssl/sm3.h>  // 使用GmSSL的SM3实现
#include <gmssl/hex.h>
#include "../../include/common.h"

// 如果GmSSL库没有定义SM3_DIGEST_LENGTH，我们自己定义它
#ifndef SM3_DIGEST_LENGTH
#define SM3_DIGEST_LENGTH 32  // SM3哈希长度为32字节(256位)
#endif

/**
 * 生成随机盐值 - 增强版本
 */
void generate_salt(char* salt, int length) {
    if (!salt || length <= 0) {
        fprintf(stderr, "错误: 无效的盐值缓冲区或长度\n");
        return;
    }
    
    const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()";
    int charset_size = sizeof(charset) - 1;
    
    // 使用时间加随机种子
    unsigned int seed = (unsigned int)time(NULL);
    seed = seed ^ (seed << 13);
    seed = seed ^ (seed >> 17);
    seed = seed ^ (seed << 5);
    srand(seed);
    
    // 生成随机盐值
    for (int i = 0; i < length; i++) {
        salt[i] = charset[rand() % charset_size];
    }
    salt[length] = '\0';
    
    fprintf(stderr, "生成的盐值: %s\n", salt);
}

/**
 * 使用SM3算法哈希密码
 */
void hash_password(const char* password, const char* salt, char* output_hash) {
    if (!password || !salt || !output_hash) {
        fprintf(stderr, "错误: hash_password函数接收到空指针\n");
        if (output_hash) {
            strcpy(output_hash, "ERROR");
        }
        return;
    }
    
    // 计算密码和盐值的长度
    size_t password_len = strlen(password);
    size_t salt_len = strlen(salt);
    
    // 安全检查
    if (password_len == 0 || salt_len == 0 || password_len > 1000 || salt_len > 100) {
        fprintf(stderr, "错误: 密码或盐值长度异常\n");
        strcpy(output_hash, "ERROR");
        return;
    }
    
    fprintf(stderr, "哈希密码 - 密码长度: %lu, 盐值长度: %lu\n", password_len, salt_len);
    
    // 创建拼接缓冲区：盐值+密码
    char combined[1200] = {0};
    
    // 安全地拼接字符串
    strncpy(combined, salt, 100);
    combined[100] = '\0'; // 确保以null结尾
    strncat(combined, password, 1000);
    
    // 使用SM3哈希
    SM3_CTX ctx;
    unsigned char hash[SM3_DIGEST_LENGTH];
    
    sm3_init(&ctx);
    sm3_update(&ctx, (unsigned char*)combined, strlen(combined));
    sm3_finish(&ctx, hash);
    
    // 将二进制哈希转换为十六进制字符串
    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[SM3_DIGEST_LENGTH * 2] = '\0';
    
    fprintf(stderr, "生成的SM3密码哈希: %s\n", output_hash);
}
