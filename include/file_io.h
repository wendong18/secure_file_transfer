#ifndef FILE_IO_H
#define FILE_IO_H

#include <sys/types.h>

/**
 * 将 buf 写入 path 文件（覆盖），成功返回 0
 */
int write_file(const char* path, const unsigned char* buf, size_t len);

/**
 * 从 path 读取整个文件到 *buf，返回文件字节数，失败返回 -1
 * 调用者负责 free(*buf)
 */
ssize_t read_file(const char* path, unsigned char** buf);

#endif // FILE_IO_H
