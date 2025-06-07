#ifndef COMMON_H
#define COMMON_H

#define DB_PATH "secure_file_transfer.db"
#define SALT_LEN 16
#define HASH_LEN 65
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64

typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} UserInfo;

void generate_salt(char* salt, int length);
void hash_password(const char* password, const char* salt, char* output_hash);

#endif
