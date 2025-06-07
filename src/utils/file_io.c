#include "../../include/file_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#define open _open
#define close _close
#define read _read
#define write _write
#define O_RDONLY _O_RDONLY
#define O_CREAT _O_CREAT
#define O_WRONLY _O_WRONLY
#define O_TRUNC _O_TRUNC
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#else
#include <unistd.h>
#endif

int write_file(const char* path, const unsigned char* buf, size_t len) {
    int fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "Error opening file for writing: %s - %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t w = write(fd, buf, len);
    close(fd);
    if (w != (ssize_t)len) {
        fprintf(stderr, "Error writing file: %s - %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

ssize_t read_file(const char* path, unsigned char** buf) {
    if (!path || !buf) {
        fprintf(stderr, "Invalid parameters to read_file\n");
        return -1;
    }
    
    fprintf(stderr, "Reading file: %s\n", path);
    
#ifdef _WIN32
    // 使用Windows API处理文件
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to open file: %s, error code: %lu\n", path, GetLastError());
        return -1;
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        fprintf(stderr, "Failed to get file size: %s, error code: %lu\n", path, GetLastError());
        CloseHandle(hFile);
        return -1;
    }
    
    if (fileSize.QuadPart > SIZE_MAX) {
        fprintf(stderr, "File too large to read: %s\n", path);
        CloseHandle(hFile);
        return -1;
    }
    
    *buf = (unsigned char*)malloc((size_t)fileSize.QuadPart);
    if (!*buf) {
        fprintf(stderr, "Failed to allocate memory for file: %s\n", path);
        CloseHandle(hFile);
        return -1;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, *buf, (DWORD)fileSize.QuadPart, &bytesRead, NULL)) {
        fprintf(stderr, "Failed to read file: %s, error code: %lu\n", path, GetLastError());
        free(*buf);
        *buf = NULL;
        CloseHandle(hFile);
        return -1;
    }
    
    CloseHandle(hFile);
    fprintf(stderr, "Successfully read %lu bytes from file: %s\n", bytesRead, path);
    return bytesRead;
#else
    // 使用标准POSIX API
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file: %s - %s\n", path, strerror(errno));
        return -1;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) { 
        fprintf(stderr, "Failed to stat file: %s - %s\n", path, strerror(errno));
        close(fd); 
        return -1; 
    }
    
    *buf = malloc(st.st_size);
    if (!*buf) { 
        fprintf(stderr, "Failed to allocate memory for file: %s\n", path);
        close(fd); 
        return -1; 
    }
    
    ssize_t r = read(fd, *buf, st.st_size);
    close(fd);
    
    if (r < 0) {
        fprintf(stderr, "Failed to read file: %s - %s\n", path, strerror(errno));
        free(*buf);
        *buf = NULL;
        return -1;
    }
    
    fprintf(stderr, "Successfully read %zd bytes from file: %s\n", r, path);
    return r;
#endif
}
