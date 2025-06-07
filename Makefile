# Makefile for Secure File Transfer System (Phases 1–3)

# -----------------------------------------------------------------------------
# Compiler and flags
# -----------------------------------------------------------------------------
CC          := gcc
CXX         := g++
INCLUDES    := -I./include -I./src # Added -I./src for internal headers
CFLAGS      := -Wall -Wextra -g -O2
CXXFLAGS    := $(CFLAGS) -fPIC

# 链接库设置
LIBS        := -lsqlite3 -lssl -lcrypto -lgmssl

# 检查是否是Windows系统，添加Windows特有的库
ifeq ($(OS),Windows_NT)
    LIBS += -lws2_32 -lgdi32
endif

QT_CFLAGS   := $(shell pkg-config --cflags Qt5Widgets Qt5Network)
QT_LIBS     := $(shell pkg-config --libs Qt5Widgets Qt5Network)

# 添加pthread库链接
SERVER_LDFLAGS := $(LIBS) -lpthread

# -----------------------------------------------------------------------------
# Source files
# -----------------------------------------------------------------------------
DB_SRC         := src/db/db_init.c        \
                  src/db/user_auth.c      \
                  src/db/file_manager.c

UTIL_SRC       := src/utils/sm3.c         \
                  src/utils/sm2.c         \
                  src/utils/file_io.c

APP_SRC        := app.c  # 替换原来的src/main.c

SERVER_SRC     := src/server/server_main.c   \
                  src/server/server_socket.c

CLIENT_COMMON  := src/client/client_socket.c
CLIENT_GUI_SRC := src/client/client_main.cpp \
                  src/client/mainwindow.cpp

# Define the path for the MOC generated file
MOC_GENERATED_CPP := src/client/moc_client_main.cpp
MOC_MAINWINDOW_CPP := src/client/moc_mainwindow.cpp

# -----------------------------------------------------------------------------
# Object files
# -----------------------------------------------------------------------------
DB_OBJS          := $(DB_SRC:.c=.o)
UTIL_OBJS        := $(UTIL_SRC:.c=.o)
APP_OBJ          := $(APP_SRC:.c=.o)

SERVER_OBJS      := $(SERVER_SRC:.c=.o) $(DB_OBJS) $(UTIL_OBJS)

# MOC generated object file
MOC_GENERATED_OBJ := $(MOC_GENERATED_CPP:.cpp=.o)
MOC_MAINWINDOW_OBJ := $(MOC_MAINWINDOW_CPP:.cpp=.o)

# Client GUI object files: original client_main.o and the MOC generated object
CLIENT_GUI_OBJS  := $(CLIENT_COMMON:.c=.o) src/utils/file_io.o src/utils/sm2.o src/utils/sm3.o src/client/client_main.o src/client/mainwindow.o $(MOC_GENERATED_OBJ) $(MOC_MAINWINDOW_OBJ)

# -----------------------------------------------------------------------------
# Phony targets
# -----------------------------------------------------------------------------
.PHONY: all clean

all: app server client # Keep all targets for completeness

# -----------------------------------------------------------------------------
# Phase 1: CLI 注册/登录 (app) - 修改为使用新的app.c
# -----------------------------------------------------------------------------
app: $(APP_OBJ) $(DB_OBJS) src/utils/sm3.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# -----------------------------------------------------------------------------
# Phase 2: 多进程 Socket 服务端 (server)
# -----------------------------------------------------------------------------
server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(SERVER_LDFLAGS)

# -----------------------------------------------------------------------------
# Phase 2: Qt 登录客户端 (client)
# -----------------------------------------------------------------------------
client: $(CLIENT_GUI_OBJS)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) $^ -o $@ $(LIBS) $(QT_LIBS)

# -----------------------------------------------------------------------------
# Phase 3: CLI 文件上传/下载 - Assuming these are still needed if 'app' is
# -----------------------------------------------------------------------------
# Add if you have client_upload and client_download source files.
# If these are not used/needed, remove them from the 'all' target above and related SRC/OBJS.
# UPLOAD_MAIN_SRC   := src/client/client_upload_main.c
# DOWNLOAD_MAIN_SRC := src/client/client_download_main.c
# UPLOAD_OBJS      := src/client/client_upload_main.o \
#                     src/client/client_socket.o     \
#                     src/utils/file_io.o
# DOWNLOAD_OBJS    := src/client/client_download_main.o \
#                     src/client/client_socket.o       \
#                     src/utils/file_io.o
# client_upload: $(UPLOAD_OBJS)
# 	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
# client_download: $(DOWNLOAD_OBJS)
# 	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# -----------------------------------------------------------------------------
# Generic compilation rules
# -----------------------------------------------------------------------------
# C source -> object
src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 添加编译根目录下的app.c的规则
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# C++ source -> object (for mainwindow.cpp)
src/client/mainwindow.o: src/client/mainwindow.cpp src/client/mainwindow.h $(MOC_MAINWINDOW_CPP)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -c $< -o $@

# Qt GUI client main (original .cpp to .o)
# This rule now explicitly depends on the MOC generated .cpp file to ensure it's made first.
src/client/client_main.o: src/client/client_main.cpp $(MOC_GENERATED_CPP)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -c $< -o $@

# MOC rule: generates the moc_*.cpp file in src/client/
$(MOC_GENERATED_CPP): src/client/client_main.cpp
	moc $< -o $@

# Rule to compile the moc_*.cpp file into an object file
$(MOC_GENERATED_OBJ): $(MOC_GENERATED_CPP)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -c $< -o $@

# MOC rule: generates the moc_*.cpp file in src/client/
$(MOC_MAINWINDOW_CPP): src/client/mainwindow.h
	moc $< -o $@

# Rule to compile the moc_*.cpp file into an object file
$(MOC_MAINWINDOW_OBJ): $(MOC_MAINWINDOW_CPP)
	$(CXX) $(CXXFLAGS) $(QT_CFLAGS) -c $< -o $@

# -----------------------------------------------------------------------------
# Clean up
# -----------------------------------------------------------------------------
clean:
	find src -name '*.o' -delete
	rm -f app.o
	rm -f app server client # Add other executables here if you enable them
	rm -f src/client/moc_client_main.cpp # Remove the MOC generated source file
	rm -f src/client/moc_mainwindow.cpp

