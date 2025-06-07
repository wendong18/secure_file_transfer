#include "mainwindow.h"
#include <QCryptographicHash>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QBuffer>
#include <QProgressDialog>
#include <QThread>
#include <QTimer>
#include <QtNetwork/QNetworkInterface>
#include <QInputDialog>
#include <QDebug>
#include <QtNetwork/QHostAddress>
#include <QMessageBox>
#include <QPushButton>
#include <QEventLoop>
#include <QDialogButtonBox>
#include <QRandomGenerator>
#include <QProcess>
#include <QTemporaryFile>
#include <QTextStream>
#include <QApplication>
#include <QFuture>
#include <QtConcurrent/QtConcurrent>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <io.h>
// Windows下定义EAGAIN和EWOULDBLOCK
#ifndef EAGAIN
#define EAGAIN WSAEWOULDBLOCK
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
// Windows下使用closesocket替代close
#define close(s) closesocket(s)
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
// POSIX平台需要显式声明send和recv函数
extern ssize_t send(int sockfd, const void *buf, size_t len, int flags);
extern ssize_t recv(int sockfd, void *buf, size_t len, int flags);
#endif

// 从common.h引入这些常量，确保与服务器端一致
#ifndef MAX_USERNAME_LEN
#define MAX_USERNAME_LEN 64
#endif

#ifndef MAX_PASSWORD_LEN 
#define MAX_PASSWORD_LEN 64
#endif

// 添加外部C函数声明
extern "C" {
    int connect_to_server(const char* ip, int port);
    int login(int sockfd, const char* username, const char* password);
    int upload_file(int sockfd, const char* local_path, const char* remote_name);
    int upload_file_with_access(int sockfd, const char* local_path, const char* remote_name, const char* access_level);
    int download_file(int sockfd, const char* remote_name, const char* local_path);
    int get_file_list(int sockfd, char* result, int maxlen);
    int get_logs(int sockfd, char* result, int maxlen);
    int register_user(int sfd, const char* username, const char* password);
    int delete_user(int sockfd, const char* username);
    int admin_delete_file(int sockfd, const char* filename);
    int change_user_role(int sockfd, const char* username, const char* role);
    int sm2_generate_keypair(char* privkey_hex, char* pubkey_hex);
    int sm2_sign_data(const uint8_t* data, size_t data_len, const char* privkey_hex, char* sig_hex);
    int sm2_verify_signature(const uint8_t* data, size_t data_len, const char* pubkey_hex, const char* sig_hex);
    int sm2_hybrid_encrypt(const uint8_t* data, size_t data_len, const char* pubkey_hex, uint8_t* encrypted, size_t* encrypted_len);
    int sm2_hybrid_decrypt(const uint8_t* encrypted, size_t encrypted_len, const char* privkey_hex, uint8_t* decrypted, size_t* decrypted_len);
}

// 获取本机IP地址
QString getLocalIP() {
    QString localIP = "127.0.0.1";
    for(const QHostAddress &address : QNetworkInterface::allAddresses()) {
        if(address.protocol() == QAbstractSocket::IPv4Protocol && address != QHostAddress::LocalHost)
            return address.toString();
    }
    return localIP;
}

// 获取服务器地址
QString getServerIP() {
    return "127.0.0.1"; // 默认连接本地服务器
}

MainWindow::MainWindow(QWidget* parent) : QWidget(parent) {
    stack = new QStackedWidget(this);
    setupLogin();
    setupRegister();
    setupMain();
    setupLogs();
    setupUserManage();
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(stack);
    setLayout(mainLayout);
    stack->setCurrentWidget(loginWidget);
    
    // 初始化随机数生成器 - 使用QRandomGenerator替代qsrand
    QRandomGenerator::securelySeeded();
}

void MainWindow::setupLogin() {
    loginWidget = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(loginWidget);
    
    QLabel* titleLabel = new QLabel("安全文件传输系统");
    titleLabel->setAlignment(Qt::AlignCenter);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    
    loginUser = new QLineEdit();
    loginUser->setPlaceholderText("用户名");
    loginPass = new QLineEdit();
    loginPass->setPlaceholderText("密码");
    loginPass->setEchoMode(QLineEdit::Password);
    
    QPushButton* loginBtn = new QPushButton("登录");
    QPushButton* regBtn = new QPushButton("注册");
    
    layout->addWidget(titleLabel);
    layout->addWidget(loginUser);
    layout->addWidget(loginPass);
    layout->addWidget(loginBtn);
    layout->addWidget(regBtn);
    
    connect(loginBtn, &QPushButton::clicked, this, &MainWindow::doLogin);
    connect(regBtn, &QPushButton::clicked, [this]() {
        stack->setCurrentWidget(registerWidget);
    });
    
    stack->addWidget(loginWidget);
}

void MainWindow::setupRegister() {
    registerWidget = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(registerWidget);
    
    QLabel* titleLabel = new QLabel("用户注册");
    titleLabel->setAlignment(Qt::AlignCenter);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    
    regUser = new QLineEdit();
    regUser->setPlaceholderText("用户名");
    regPass = new QLineEdit();
    regPass->setPlaceholderText("密码");
    regPass->setEchoMode(QLineEdit::Password);
    
    QPushButton* regSubmitBtn = new QPushButton("提交注册");
    QPushButton* backBtn = new QPushButton("返回登录");
    
    layout->addWidget(titleLabel);
    layout->addWidget(regUser);
    layout->addWidget(regPass);
    layout->addWidget(regSubmitBtn);
    layout->addWidget(backBtn);
    
    connect(regSubmitBtn, &QPushButton::clicked, this, &MainWindow::doRegister);
    connect(backBtn, &QPushButton::clicked, [this]() {
        stack->setCurrentWidget(loginWidget);
    });
    
    stack->addWidget(registerWidget);
}

void MainWindow::setupMain() {
    mainWidget = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(mainWidget);
    
    // 用户信息标签
    mainUserLabel = new QLabel("用户: " + currentUser);
    mainUserLabel->setAlignment(Qt::AlignLeft);
    QFont labelFont = mainUserLabel->font();
    labelFont.setBold(true);
    mainUserLabel->setFont(labelFont);
    layout->addWidget(mainUserLabel);
    
    // 功能按钮区域
    QHBoxLayout *btnLayout = new QHBoxLayout();
    
    QPushButton *refreshBtn = new QPushButton("刷新文件列表");
    QPushButton *uploadBtn = new QPushButton("上传文件");
    QPushButton *downloadBtn = new QPushButton("下载文件");
    QPushButton *deleteBtn = new QPushButton("删除文件");
    QPushButton *searchBtn = new QPushButton("搜索文件");
    QPushButton *logsBtn = new QPushButton("查看日志");
    QPushButton *changePassBtn = new QPushButton("修改密码");
    QPushButton *userManageBtn = new QPushButton("用户管理");
    QPushButton *logoutBtn = new QPushButton("退出登录");
    
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::refreshFiles);
    connect(uploadBtn, &QPushButton::clicked, this, &MainWindow::doUpload);
    connect(downloadBtn, &QPushButton::clicked, this, &MainWindow::doDownload);
    connect(deleteBtn, &QPushButton::clicked, this, &MainWindow::doDeleteFile);
    connect(searchBtn, &QPushButton::clicked, this, &MainWindow::doSearchFiles);
    connect(logsBtn, &QPushButton::clicked, this, &MainWindow::viewLogs);
    connect(changePassBtn, &QPushButton::clicked, this, &MainWindow::doChangePassword);
    connect(userManageBtn, &QPushButton::clicked, this, &MainWindow::showMain);
    connect(logoutBtn, &QPushButton::clicked, this, &MainWindow::doLogout);
    
    btnLayout->addWidget(refreshBtn);
    btnLayout->addWidget(uploadBtn);
    btnLayout->addWidget(downloadBtn);
    btnLayout->addWidget(deleteBtn);
    btnLayout->addWidget(searchBtn);
    btnLayout->addWidget(logsBtn);
    btnLayout->addWidget(changePassBtn);
    btnLayout->addWidget(userManageBtn);
    btnLayout->addWidget(logoutBtn);
    
    layout->addLayout(btnLayout);
    
    // 文件表格
    fileTable = new QTableWidget();
    fileTable->setColumnCount(3);
    fileTable->setHorizontalHeaderLabels({"文件名", "上传时间", "访问权限"});
    fileTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    fileTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fileTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    
    layout->addWidget(fileTable);
    
    stack->addWidget(mainWidget);
}

void MainWindow::setupLogs() {
    logWidget = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(logWidget);
    
    QLabel* titleLabel = new QLabel("操作日志");
    titleLabel->setAlignment(Qt::AlignCenter);
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    
    logTable = new QTableWidget();
    logTable->setColumnCount(5);
    logTable->setHorizontalHeaderLabels({"时间", "用户", "操作", "文件", "IP"});
    logTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    
    QPushButton* backBtn = new QPushButton("返回");
    
    layout->addWidget(titleLabel);
    layout->addWidget(logTable);
    layout->addWidget(backBtn);
    
    connect(backBtn, &QPushButton::clicked, [this]() {
        stack->setCurrentWidget(mainWidget);
    });
    
    stack->addWidget(logWidget);
}

void MainWindow::setupUserManage() {
    userManageWidget = new QWidget;
    QVBoxLayout* layout = new QVBoxLayout(userManageWidget);
    
    // 标题
    QLabel* titleLabel = new QLabel("用户管理");
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    layout->addWidget(titleLabel);
    
    // 用户表格
    userTable = new QTableWidget;
    userTable->setColumnCount(4);
    userTable->setHorizontalHeaderLabels({"用户名", "注册时间", "角色", "操作"});
    userTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    layout->addWidget(userTable);
    
    // 按钮
    QHBoxLayout* btnLayout = new QHBoxLayout;
    QPushButton* refreshBtn = new QPushButton("刷新");
    QPushButton* backBtn = new QPushButton("返回主界面");
    btnLayout->addWidget(refreshBtn);
    btnLayout->addWidget(backBtn);
    layout->addLayout(btnLayout);
    
    // 连接信号
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::refreshUsers);
    connect(backBtn, &QPushButton::clicked, this, [=](){ stack->setCurrentWidget(mainWidget); });
    
    stack->addWidget(userManageWidget);
}

void MainWindow::setupAdminControls() {
    if (!isAdmin) return;
    
    // 添加管理员特有的控件
    QHBoxLayout* adminLayout = new QHBoxLayout;
    QPushButton* userManageBtn = new QPushButton("用户管理");
    QPushButton* systemLogBtn = new QPushButton("系统日志");
    adminLayout->addWidget(userManageBtn);
    adminLayout->addWidget(systemLogBtn);
    
    // 获取mainWidget的布局
    QVBoxLayout* mainLayout = qobject_cast<QVBoxLayout*>(mainWidget->layout());
    if (mainLayout) {
        mainLayout->insertLayout(1, adminLayout); // 在用户标签下方插入管理员控件
    }
    
    // 为文件列表添加删除按钮
    for (int i = 0; i < fileTable->rowCount(); i++) {
        QWidget* widget = new QWidget;
        QHBoxLayout* layout = new QHBoxLayout(widget);
        QPushButton* dlBtn = new QPushButton("下载");
        QPushButton* delBtn = new QPushButton("删除");
        
        connect(dlBtn, &QPushButton::clicked, this, [=](){
            QString fileName = fileTable->item(i, 0)->text();
            downloadFile(fileName, QDir::homePath() + "/" + fileName);
        });
        
        connect(delBtn, &QPushButton::clicked, this, [=](){
            QString fileName = fileTable->item(i, 0)->text();
            deleteFile(fileName);
        });
        
        layout->addWidget(dlBtn);
        layout->addWidget(delBtn);
        layout->setContentsMargins(0, 0, 0, 0);
        fileTable->setCellWidget(i, 3, widget);
    }
    
    // 连接用户管理按钮
    connect(userManageBtn, &QPushButton::clicked, this, &MainWindow::showMain);
    
    // 连接系统日志按钮
    connect(systemLogBtn, &QPushButton::clicked, this, &MainWindow::viewLogs);
}

void MainWindow::showMain() {
    if (!isAdmin) {
        QMessageBox::warning(this, "错误", "您没有访问用户管理的权限");
        return;
    }
    
    refreshUsers();
    stack->setCurrentWidget(userManageWidget);
}

void MainWindow::refreshUsers() {
    // 连接服务器
    int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
    if (sfd < 0) {
        QMessageBox::warning(this, "错误", "连接服务器失败");
        return;
    }
    
    // 登录
    if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
        QMessageBox::warning(this, "错误", "身份验证失败");
        ::close(sfd);
        return;
    }
    
    // 获取用户列表
    char result[4096] = {0};
    int n = get_user_list(sfd, result, sizeof(result) - 1);
    ::close(sfd);
    
    if (n <= 0) {
        QMessageBox::warning(this, "错误", "获取用户列表失败");
        return;
    }
    
    // 清空表格
    userTable->setRowCount(0);
    
    // 解析JSON数据
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray(result), &error);
    
    if (error.error != QJsonParseError::NoError) {
        QMessageBox::warning(this, "错误", "解析用户数据失败: " + error.errorString());
        return;
    }
    
    if (!doc.isArray()) {
        QMessageBox::warning(this, "错误", "用户数据格式错误");
        return;
    }
    
    QJsonArray users = doc.array();
    
    // 填充表格
    for (int i = 0; i < users.size(); i++) {
        QJsonObject user = users[i].toObject();
        
        QString username = user["username"].toString();
        QString registerTime = user["register_time"].toString();
        bool isAdmin = user["is_admin"].toBool();
        
        int row = userTable->rowCount();
        userTable->insertRow(row);
        userTable->setItem(row, 0, new QTableWidgetItem(username));
        userTable->setItem(row, 1, new QTableWidgetItem(registerTime));
        userTable->setItem(row, 2, new QTableWidgetItem(isAdmin ? "管理员" : "普通用户"));
        
        QWidget* widget = new QWidget;
        QHBoxLayout* layout = new QHBoxLayout(widget);
        
        // 添加删除按钮
        QPushButton* delBtn = new QPushButton("删除");
        
        // 管理员不能删除自己
        if (username == currentUser) {
            delBtn->setEnabled(false);
            delBtn->setToolTip("不能删除当前登录账号");
        }
        
        connect(delBtn, &QPushButton::clicked, this, [=](){
            deleteUser(username);
        });
        
        layout->addWidget(delBtn);
        layout->setContentsMargins(0, 0, 0, 0);
        userTable->setCellWidget(row, 3, widget);
    }
}

void MainWindow::changeUserRole(const QString &username, const QString &role) {
    // 连接服务器
    int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
    if (sfd < 0) {
        QMessageBox::warning(this, "错误", "连接服务器失败");
        return;
    }
    
    // 实际应该发送更改角色请求到服务器
    // 这里简单模拟成功
    QMessageBox::information(this, "角色更改", "已将用户 " + username + " 的角色更改为 " + role);
    
    ::close(sfd);
    refreshUsers();
}

void MainWindow::doLogin() {
    QString username = loginUser->text().trimmed();
    QString password = loginPass->text();
    
    if(username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "错误", "用户名和密码不能为空");
        return;
    }
    
    qDebug() << "尝试登录，用户名：" << username;
    
    // 创建进度对话框，使用堆分配
    QProgressDialog* progress = new QProgressDialog("正在连接服务器...", "取消", 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->show();
    
    // 异步处理登录 - 使用值捕获progress指针
    QTimer::singleShot(100, this, [this, username, password, progress]() {
        int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
        if(sfd < 0) {
            progress->close();
            progress->deleteLater();
            qDebug() << "连接服务器失败";
            QMessageBox::critical(this, "错误", "无法连接到服务器");
            return;
        }
        
        qDebug() << "成功连接到服务器，正在发送登录请求";
        
        // 避免中文编码问题，确保使用UTF-8编码
        QByteArray usernameUtf8 = username.toUtf8();
        QByteArray passwordUtf8 = password.toUtf8();
        
        // 打印登录详情（实际生产环境中应移除密码日志）
        qDebug() << "登录信息 - 用户名长度:" << usernameUtf8.length() 
                 << "密码长度:" << passwordUtf8.length();
        
        // 使用try-catch块捕获可能的段错误
        try {
            // 尝试登录
            int loginResult = login(sfd, usernameUtf8.constData(), passwordUtf8.constData());
            ::close(sfd);
            
            progress->close();
            progress->deleteLater();
            
            if(loginResult > 0) {  // 登录成功
                qDebug() << "登录成功，用户：" << username;
                currentUser = username;
                currentPass = password; // 保存密码用于后续操作
                
                // 使用login函数返回值确定是否为管理员
                // loginResult=1表示普通用户，loginResult=2表示管理员
                isAdmin = (loginResult == 2);
                
                qDebug() << "用户权限：" << (isAdmin ? "管理员" : "普通用户");
                
                mainUserLabel->setText("当前用户：" + username);
                
                // 先切换界面，再强制更新UI
                stack->setCurrentWidget(mainWidget);
                QApplication::processEvents();
                
                // 刷新文件列表
                refreshFiles();
            } else if(loginResult == -2) {  // 密码错误
                qDebug() << "登录失败，密码错误，用户：" << username;
                QMessageBox::warning(this, "登录失败", "密码错误");
            } else {  // 其他错误
                qDebug() << "登录失败，可能是网络问题，用户：" << username;
                
                // 再次尝试登录，考虑到可能是网络问题
                sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
                if(sfd >= 0) {
                    qDebug() << "重试登录...";
                    loginResult = login(sfd, usernameUtf8.constData(), passwordUtf8.constData());
                    ::close(sfd);
                    
                    if(loginResult == 1) {  // 登录成功
                        qDebug() << "重试登录成功";
                        currentUser = username;
                        currentPass = password; 
                        isAdmin = (loginResult == 2); // 使用login函数返回值判断是否为管理员
                        qDebug() << "用户权限：" << (isAdmin ? "管理员" : "普通用户");
                        mainUserLabel->setText("当前用户：" + username);
                        
                        // 先切换界面，再强制更新UI
                        stack->setCurrentWidget(mainWidget);
                        QApplication::processEvents();
                        
                        // 刷新文件列表
                        refreshFiles();
                        return;
                    } else if(loginResult == -2) {  // 密码错误
                        QMessageBox::warning(this, "登录失败", "密码错误");
                    } else {  // 其他错误
                        QMessageBox::warning(this, "登录失败", "连接服务器失败");
                    }
                } else {
                    QMessageBox::warning(this, "登录失败", "连接服务器失败");
                }
            }
        } catch (...) {
            // 捕获所有异常
            ::close(sfd);
            progress->close();
            progress->deleteLater();
            qDebug() << "登录过程中发生异常";
            QMessageBox::critical(this, "错误", "登录过程中发生未知错误");
        }
    });
}

void MainWindow::doRegister() {
    QString username = regUser->text();
    QString password = regPass->text();
    
    if(username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "错误", "用户名和密码不能为空");
        return;
    }
    
    if(password.length() < 6) {
        QMessageBox::warning(this, "错误", "密码长度必须至少为6个字符");
        return;
    }
    
    // 检查用户名是否只包含有效字符
    QRegExp validUsername("[a-zA-Z0-9_]+");
    if(!validUsername.exactMatch(username)) {
        QMessageBox::warning(this, "错误", "用户名只能包含字母、数字和下划线");
        return;
    }
    
    // 验证用户名长度
    if(username.length() < 3) {
        QMessageBox::warning(this, "错误", "用户名长度必须至少为3个字符");
        return;
    }
    
    qDebug() << "尝试注册新用户：" << username;
    
    // 创建进度对话框
    QProgressDialog* progress = new QProgressDialog("正在连接服务器...", "取消", 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->show();
    
    // 使用值捕获progress指针，避免悬空引用
    QTimer::singleShot(100, this, [this, username, password, progress]() {
        int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
        if(sfd < 0) {
            progress->close();
            progress->deleteLater();
            qDebug() << "连接服务器失败";
            QMessageBox::critical(this, "错误", "无法连接到服务器");
            return;
        }
        
        qDebug() << "成功连接到服务器，正在发送注册请求";
        
        // 避免中文编码问题，确保使用UTF-8编码
        QByteArray usernameUtf8 = username.toUtf8();
        QByteArray passwordUtf8 = password.toUtf8();
        
        // 打印注册详情（实际生产环境中应移除密码日志）
        qDebug() << "注册信息 - 用户名长度:" << usernameUtf8.length() 
                 << "密码长度:" << passwordUtf8.length();
        
        // 安全检查 - 确保用户名和密码长度合适
        if (usernameUtf8.length() < 3 || usernameUtf8.length() >= MAX_USERNAME_LEN) {
            progress->close();
            progress->deleteLater();
            QMessageBox::warning(this, "注册失败", "用户名长度必须在3到31个字符之间");
            ::close(sfd);
            return;
        }
        
        if (passwordUtf8.length() < 6 || passwordUtf8.length() >= MAX_PASSWORD_LEN) {
            progress->close();
            progress->deleteLater();
            QMessageBox::warning(this, "注册失败", "密码长度必须在6到63个字符之间");
            ::close(sfd);
            return;
        }
        
        // 使用try-catch块捕获可能的段错误
        try {
            // 尝试注册
            int result = register_user(sfd, usernameUtf8.constData(), passwordUtf8.constData());
            ::close(sfd);
            
            progress->close();
            progress->deleteLater();
            
            if(result == 0) {
                qDebug() << "注册成功，用户：" << username;
                
                // 先切换到登录页面
                loginUser->setText(username);
                loginPass->setText(password);
                stack->setCurrentWidget(loginWidget);
                
                // 强制更新UI
                QApplication::processEvents();
                
                // 显示成功消息
                QMessageBox::information(this, "注册成功", "用户注册成功，请登录");
            } else {
                qDebug() << "注册失败，用户：" << username;
                QMessageBox::warning(this, "注册失败", "用户注册失败，可能是用户名已存在或服务器内部错误");
            }
        } catch (...) {
            // 捕获所有异常
            ::close(sfd);
            progress->close();
            progress->deleteLater();
            qDebug() << "注册过程中发生异常";
            QMessageBox::critical(this, "错误", "注册过程中发生未知错误");
        }
    });
}

void MainWindow::refreshFiles() {
    qDebug() << "开始刷新文件列表...";
    
    // 创建进度对话框，使用堆分配
    QProgressDialog* progress = new QProgressDialog("正在获取文件列表...", "取消", 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->show();
    
    QTimer::singleShot(100, this, [this, progress]() {
        qDebug() << "连接服务器获取文件列表";
        int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
        if(sfd < 0) {
            progress->close();
            progress->deleteLater();
            qDebug() << "连接服务器失败";
            QMessageBox::critical(this, "错误", "无法连接到服务器");
            return;
        }
        
        qDebug() << "尝试使用凭据登录 - 用户名:" << currentUser;
        
        // 转换为UTF-8编码
        QByteArray usernameUtf8 = currentUser.toUtf8();
        QByteArray passwordUtf8 = currentPass.toUtf8();
        
        try {
            int loginResult = login(sfd, usernameUtf8.constData(), passwordUtf8.constData());
            if(loginResult <= 0) {  // 登录失败
                progress->close();
                progress->deleteLater();
                if(loginResult == -2) {
                    qDebug() << "密码错误，无法获取文件列表";
                    QMessageBox::warning(this, "密码错误", "密码错误，无法获取文件列表");
                } else {
                    qDebug() << "登录失败，无法获取文件列表";
                    QMessageBox::warning(this, "错误", "登录失败，无法获取文件列表");
                }
                ::close(sfd);
                return;
            }
            
            // 更新管理员状态 - 重要：确保在所有函数中都统一判断管理员身份
            isAdmin = (loginResult == 2);
            qDebug() << "登录成功，用户权限：" << (isAdmin ? "管理员" : "普通用户");
            qDebug() << "正在获取文件列表";
            
            // 使用更大的缓冲区
            char fileListJson[8192] = {0};
            int result = get_file_list(sfd, fileListJson, sizeof(fileListJson));
            ::close(sfd);
            
            progress->close();
            progress->deleteLater();
            
            qDebug() << "文件列表获取结果：" << result << " 内容：" << fileListJson;
            
            // 如果返回结果小于0，表示出错
            if(result < 0) {
                QMessageBox::warning(this, "错误", "获取文件列表失败");
                return;
            }
            
            // 处理空数据情况
            if(result == 0 || strcmp(fileListJson, "") == 0) {
                qDebug() << "文件列表为空数据";
                fileTable->clearContents();
                fileTable->setRowCount(0);
                return;
            }
            
            // 处理空数组情况
            if(strcmp(fileListJson, "[]") == 0) {
                qDebug() << "文件列表为空数组";
                fileTable->clearContents();
                fileTable->setRowCount(0);
                return;
            }
            
            // 安全检查 - 确保数据是有效的JSON数组
            if(fileListJson[0] != '[') {
                qDebug() << "返回的文件列表格式不正确：" << fileListJson;
                QMessageBox::warning(this, "错误", "文件列表格式不正确");
                fileTable->clearContents();
                fileTable->setRowCount(0);
                return;
            }
            
            // 手动解析并处理文件列表
            onFileListReceived(QString::fromUtf8(fileListJson));
        } catch (const std::exception& e) {
            // 捕获标准异常
            ::close(sfd);
            progress->close();
            progress->deleteLater();
            qDebug() << "获取文件列表过程中发生标准异常: " << e.what();
            QMessageBox::critical(this, "错误", QString("获取文件列表过程中发生异常: %1").arg(e.what()));
            fileTable->clearContents();
            fileTable->setRowCount(0);
        } catch (...) {
            // 捕获所有其他异常
            ::close(sfd);
            progress->close();
            progress->deleteLater();
            qDebug() << "获取文件列表过程中发生未知异常";
            QMessageBox::critical(this, "错误", "获取文件列表过程中发生未知错误");
            fileTable->clearContents();
            fileTable->setRowCount(0);
        }
    });
}

void MainWindow::doUpload() {
    QString filePath = QFileDialog::getOpenFileName(this, "选择要上传的文件");
    if(filePath.isEmpty()) return;
    
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    
    // 选择访问权限
    QStringList accessOptions = {"private", "public"};
    if(isAdmin) accessOptions.append("admin-only");
    
    QString accessType = QInputDialog::getItem(this, "选择访问权限", "为文件设置访问权限:", 
                                              accessOptions, 0, false);
    
    // 创建进度对话框，使用堆分配
    QProgressDialog* progress = new QProgressDialog("正在上传文件...", "取消", 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->show();
    
    QTimer::singleShot(100, this, [this, filePath, fileName, accessType, progress]() {
        try {
            int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
            if(sfd < 0) {
                progress->close();
                progress->deleteLater();
                QMessageBox::critical(this, "错误", "无法连接到服务器");
                return;
            }
            
            if(!login(sfd, currentUser.toUtf8().data(), currentPass.toUtf8().data())) { // 使用保存的密码
                progress->close();
                progress->deleteLater();
                QMessageBox::warning(this, "错误", "登录失败，无法上传文件");
                ::close(sfd);
                return;
            }
            
            int result = upload_file_with_access(sfd, filePath.toUtf8().data(), 
                                              fileName.toUtf8().data(), 
                                              accessType.toUtf8().data());
            ::close(sfd);
            
            progress->close();
            progress->deleteLater();
            
            if(result == 0) {
                QMessageBox::information(this, "上传成功", "文件已成功上传");
                refreshFiles();
            } else {
                QMessageBox::warning(this, "上传失败", "上传文件过程中发生错误");
            }
        } catch (const std::exception& e) {
            // 捕获标准异常
            progress->close();
            progress->deleteLater();
            qDebug() << "上传文件过程中发生标准异常: " << e.what();
            QMessageBox::critical(this, "错误", QString("上传文件过程中发生异常: %1").arg(e.what()));
        } catch (...) {
            // 捕获所有异常
            progress->close();
            progress->deleteLater();
            qDebug() << "上传文件过程中发生未知异常";
            QMessageBox::critical(this, "错误", "上传文件过程中发生未知错误");
        }
    });
}

void MainWindow::downloadFile(const QString &fileName, const QString &savePath) {
    // 创建进度对话框，使用堆分配
    QProgressDialog* progress = new QProgressDialog("正在下载文件...", "取消", 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->show();
    
    QTimer::singleShot(100, this, [this, fileName, savePath, progress]() {
        try {
            int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
            if(sfd < 0) {
                progress->close();
                progress->deleteLater();
                QMessageBox::critical(this, "错误", "无法连接到服务器");
                return;
            }
            
            if(!login(sfd, currentUser.toUtf8().data(), currentPass.toUtf8().data())) { // 使用保存的密码
                progress->close();
                progress->deleteLater();
                QMessageBox::warning(this, "错误", "登录失败，无法下载文件");
                ::close(sfd);
                return;
            }
            
            int result = download_file(sfd, fileName.toUtf8().data(), savePath.toUtf8().data());
            ::close(sfd);
            
            progress->close();
            progress->deleteLater();
            
            if(result == 0) {
                QMessageBox::information(this, "下载成功", "文件已成功下载到：\n" + savePath);
            } else {
                QMessageBox::warning(this, "下载失败", "下载文件过程中发生错误");
            }
        } catch (const std::exception& e) {
            // 捕获标准异常
            progress->close();
            progress->deleteLater();
            qDebug() << "下载文件过程中发生标准异常: " << e.what();
            QMessageBox::critical(this, "错误", QString("下载文件过程中发生异常: %1").arg(e.what()));
        } catch (...) {
            // 捕获所有异常
            progress->close();
            progress->deleteLater();
            qDebug() << "下载文件过程中发生未知异常";
            QMessageBox::critical(this, "错误", "下载文件过程中发生未知错误");
        }
    });
}

void MainWindow::viewLogs() {
    // 切换到日志界面
    stack->setCurrentWidget(logWidget);
    
    QFuture<void> future = QtConcurrent::run([this]() {
        try {
            // 创建进度对话框
            QProgressDialog progress("正在获取日志...", "取消", 0, 0);
            progress.setWindowModality(Qt::WindowModal);
            progress.show();
            
            // 连接到服务器
            int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
            if (sfd < 0) {
                progress.close();
                QMetaObject::invokeMethod(this, "showErrorMessage", 
                                         Qt::QueuedConnection,
                                         Q_ARG(QString, QString("连接服务器失败")));
                return;
            }
            
            if(!login(sfd, currentUser.toUtf8().data(), currentPass.toUtf8().data())) { // 使用保存的密码
                progress.close();
                QMetaObject::invokeMethod(this, "showErrorMessage", 
                                         Qt::QueuedConnection,
                                         Q_ARG(QString, QString("登录失败，无法获取日志")));
                ::close(sfd);
                return;
            }
            
            char logsJson[16384] = {0}; // 增大缓冲区
            int result = get_logs(sfd, logsJson, sizeof(logsJson));
            ::close(sfd);
            
            progress.close();
            
            if(result < 0) {
                QMetaObject::invokeMethod(this, "showErrorMessage", 
                                         Qt::QueuedConnection,
                                         Q_ARG(QString, QString("获取日志失败")));
                return;
            }
            
            // 安全检查：确保logsJson是有效的JSON数据
            QMetaObject::invokeMethod(this, "onLogsReceived", 
                                     Qt::QueuedConnection,
                                     Q_ARG(QString, QString::fromUtf8(logsJson)));
        } catch (const std::exception& e) {
            // 捕获标准异常
            qDebug() << "获取日志过程中发生异常: " << e.what();
            QMetaObject::invokeMethod(this, "showErrorMessage", 
                                     Qt::QueuedConnection,
                                     Q_ARG(QString, QString("获取日志过程中发生异常: %1").arg(e.what())));
        } catch (...) {
            // 捕获所有异常
            qDebug() << "获取日志过程中发生未知异常";
            QMetaObject::invokeMethod(this, "showErrorMessage", 
                                     Qt::QueuedConnection,
                                     Q_ARG(QString, QString("获取日志过程中发生未知错误")));
        }
    });
}

void MainWindow::deleteFile(const QString &fileName) {
    // 检查权限
    if (!isAdmin) {
        QMessageBox::warning(this, "错误", "您没有删除文件的权限");
        return;
    }
    
    // 确认删除
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "确认删除", 
                                 "确定要删除文件 " + fileName + " 吗？",
                                 QMessageBox::Yes|QMessageBox::No);
    if (reply != QMessageBox::Yes)
        return;
    
    // 连接服务器
    int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
    if (sfd < 0) {
        QMessageBox::warning(this, "错误", "连接服务器失败");
        return;
    }
    
    // 实际应发送删除请求到服务器
    // 这里简单模拟删除成功
    QMessageBox::information(this, "删除", "文件 " + fileName + " 已删除");
    ::close(sfd);
    
    // 刷新文件列表
    refreshFiles();
}

void MainWindow::generateSM2KeyPair() {
    // 使用SM2算法生成密钥对
    char privkey_hex[65] = {0};  // 64字符加1个终止符
    char pubkey_hex[129] = {0};  // 128字符加1个终止符
    
    // 调用C实现的SM2密钥生成函数
    if (sm2_generate_keypair(privkey_hex, pubkey_hex) != 0) {
        qDebug("SM2密钥对生成失败");
        return;
    }
    
    // 保存私钥和公钥
    currentPrivKey = QString(privkey_hex);
    currentPubKey = QString(pubkey_hex);
    
    // 调试输出
    qDebug("生成SM2密钥对: 私钥(前8字节): %s...", 
           currentPrivKey.left(16).toStdString().c_str());
    qDebug("生成SM2密钥对: 公钥(前8字节): %s...", 
           currentPubKey.left(16).toStdString().c_str());
}

QByteArray MainWindow::signData(const QByteArray &data) {
    // 使用SM2算法对数据进行签名
    
    if (currentPrivKey.isEmpty()) {
        qDebug("签名失败: 私钥不存在");
        return QByteArray();
    }
    
    // 分配签名缓冲区 (签名长度不确定，但不会超过256字节)
    char sig_hex[512] = {0};
    
    // 调用SM2签名函数
    if (sm2_sign_data((const uint8_t*)data.constData(), data.size(), 
                     currentPrivKey.toStdString().c_str(), sig_hex) != 0) {
        qDebug("SM2签名失败");
        return QByteArray();
    }
    
    return QByteArray(sig_hex);
}

bool MainWindow::verifySM2Signature(const QByteArray &data, const QByteArray &signature, const QByteArray &pubKey) {
    // 使用SM2算法验证签名
    
    // 检查参数
    if (pubKey.isEmpty() || signature.isEmpty() || data.isEmpty()) {
        qDebug("验证失败: 参数不完整");
        return false;
    }
    
    // 调用SM2验签函数
    int result = sm2_verify_signature(
        (const uint8_t*)data.constData(), data.size(),
        pubKey.constData(),
        signature.constData());
    
    if (result < 0) {
        qDebug("SM2验签处理错误");
        return false;
    }
    
    return (result == 1);
}

QByteArray MainWindow::encryptFileHybrid(const QByteArray &data, const QByteArray &recipientPubKey) {
    // 使用SM2和SM4混合加密
    
    // 检查参数
    if (data.isEmpty() || recipientPubKey.isEmpty()) {
        qDebug("混合加密失败: 参数不完整");
        return QByteArray();
    }
    
    // 估计加密后的数据大小 (SM2加密的密钥 + SM4加密的数据)
    size_t estimated_size = SM2_MAX_CIPHERTEXT_SIZE + ((data.size() + 15) / 16) * 16;
    uint8_t *encrypted = (uint8_t*)malloc(estimated_size);
    if (!encrypted) {
        qDebug("混合加密失败: 内存分配错误");
        return QByteArray();
    }
    
    // 调用混合加密函数
    size_t encrypted_len = estimated_size;
    if (sm2_hybrid_encrypt(
            (const uint8_t*)data.constData(), data.size(),
            recipientPubKey.constData(),
            encrypted, &encrypted_len) != 0) {
        qDebug("混合加密失败");
        free(encrypted);
        return QByteArray();
    }
    
    // 转换为QByteArray
    QByteArray result((const char*)encrypted, encrypted_len);
    free(encrypted);
    
    return result;
}

QByteArray MainWindow::decryptFileHybrid(const QByteArray &encryptedData) {
    // 使用SM2和SM4混合解密
    
    // 检查私钥和加密数据
    if (currentPrivKey.isEmpty() || encryptedData.isEmpty()) {
        qDebug("混合解密失败: 参数不完整");
        return QByteArray();
    }
    
    // 分配解密后的数据缓冲区 (解密后的数据总是小于等于加密数据)
    uint8_t *decrypted = (uint8_t*)malloc(encryptedData.size());
    if (!decrypted) {
        qDebug("混合解密失败: 内存分配错误");
        return QByteArray();
    }
    
    // 调用混合解密函数
    size_t decrypted_len = encryptedData.size();
    if (sm2_hybrid_decrypt(
            (const uint8_t*)encryptedData.constData(), encryptedData.size(),
            currentPrivKey.toStdString().c_str(),
            decrypted, &decrypted_len) != 0) {
        qDebug("混合解密失败");
        free(decrypted);
        return QByteArray();
    }
    
    // 转换为QByteArray
    QByteArray result((const char*)decrypted, decrypted_len);
    free(decrypted);
    
    return result;
}

// 实现文件删除功能
void MainWindow::doDeleteFile() {
    // 获取当前选择的行
    int row = fileTable->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, "错误", "请先选择要删除的文件");
        return;
    }
    
    // 获取文件名
    QString filename = fileTable->item(row, 0)->text();
    
    // 确认删除
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "确认删除", 
                                 "确定要删除文件 " + filename + " 吗？",
                                 QMessageBox::Yes | QMessageBox::No);
    
    if (reply != QMessageBox::Yes) {
        return;
    }
    
    // 创建进度对话框，使用堆分配
    QProgressDialog* progress = new QProgressDialog("正在删除文件...", "取消", 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->show();
    
    // 异步处理删除 - 使用值捕获而不是引用捕获
    QTimer::singleShot(100, this, [this, filename, progress]() {
        int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
        if(sfd < 0) {
            progress->close();
            progress->deleteLater();
            QMessageBox::critical(this, "错误", "无法连接到服务器");
            return;
        }
        
        // 登录（使用保存的凭据）
        if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
            progress->close();
            progress->deleteLater();
            QMessageBox::critical(this, "错误", "身份验证失败");
            ::close(sfd);
            return;
        }
        
        // 删除文件 - 根据用户角色选择合适的删除函数
        int result;
        if (isAdmin) {
            // 管理员使用admin_delete_file函数
            result = admin_delete_file(sfd, filename.toUtf8().constData());
        } else {
            // 普通用户使用delete_file函数
            result = delete_file(sfd, filename.toUtf8().constData());
        }
        ::close(sfd);
        
        // 处理结果
        progress->close();
        progress->deleteLater();
        if (result == 0) {
            QMessageBox::information(this, "成功", "文件已成功删除");
            refreshFiles(); // 刷新文件列表
        } else {
            QMessageBox::critical(this, "错误", "删除文件失败");
        }
    });
}

// 实现密码修改功能
void MainWindow::doChangePassword() {
    // 创建密码修改对话框
    QDialog dialog(this);
    dialog.setWindowTitle("修改密码");
    
    QVBoxLayout *layout = new QVBoxLayout(&dialog);
    
    // 当前密码
    QLabel *currentPassLabel = new QLabel("当前密码:", &dialog);
    QLineEdit *currentPassEdit = new QLineEdit(&dialog);
    currentPassEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(currentPassLabel);
    layout->addWidget(currentPassEdit);
    
    // 新密码
    QLabel *newPassLabel = new QLabel("新密码:", &dialog);
    QLineEdit *newPassEdit = new QLineEdit(&dialog);
    newPassEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(newPassLabel);
    layout->addWidget(newPassEdit);
    
    // 确认新密码
    QLabel *confirmPassLabel = new QLabel("确认新密码:", &dialog);
    QLineEdit *confirmPassEdit = new QLineEdit(&dialog);
    confirmPassEdit->setEchoMode(QLineEdit::Password);
    layout->addWidget(confirmPassLabel);
    layout->addWidget(confirmPassEdit);
    
    // 按钮
    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);
    
    // 显示对话框
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }
    
    // 验证输入
    QString currentPassword = currentPassEdit->text();
    QString newPassword = newPassEdit->text();
    QString confirmPassword = confirmPassEdit->text();
    
    if (currentPassword.isEmpty() || newPassword.isEmpty() || confirmPassword.isEmpty()) {
        QMessageBox::warning(this, "错误", "所有密码字段都必须填写");
        return;
    }
    
    if (newPassword != confirmPassword) {
        QMessageBox::warning(this, "错误", "新密码与确认密码不匹配");
        return;
    }
    
    if (newPassword.length() < 6) {
        QMessageBox::warning(this, "错误", "新密码长度必须至少为6个字符");
        return;
    }
    
    // 创建进度对话框
    QProgressDialog *progress = new QProgressDialog("正在修改密码...", "取消", 0, 0, this);
    progress->setWindowModality(Qt::WindowModal);
    progress->show();
    
    // 异步处理密码修改 - 使用值捕获而不是引用捕获
    QTimer::singleShot(100, this, [this, currentPassword, newPassword, progress]() {
        int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
        if(sfd < 0) {
            progress->close();
            progress->deleteLater();
            QMessageBox::critical(this, "错误", "无法连接到服务器");
            return;
        }
        
        // 登录（使用保存的凭据）
        if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
            progress->close();
            progress->deleteLater();
            QMessageBox::critical(this, "错误", "身份验证失败");
            ::close(sfd);
            return;
        }
        
        // 修改密码
        int result = change_password(sfd, currentUser.toUtf8().constData(), 
                                   currentPassword.toUtf8().constData(), 
                                   newPassword.toUtf8().constData());
        ::close(sfd);
        
        // 处理结果
        progress->close();
        progress->deleteLater();
        if (result == 0) {
            QMessageBox::information(this, "成功", "密码已成功修改");
            currentPass = newPassword; // 更新保存的密码
        } else if (result == -2) {
            QMessageBox::warning(this, "密码修改失败", "当前密码不正确，请重新输入");
        } else {
            QMessageBox::critical(this, "密码修改失败", "密码修改失败，服务器错误");
        }
    });
}

// 实现文件搜索功能
void MainWindow::doSearchFiles() {
    // 创建搜索对话框
    bool ok;
    QString keyword = QInputDialog::getText(this, "搜索文件", 
                                          "请输入搜索关键词:", 
                                          QLineEdit::Normal, "", &ok);
    
    if (!ok || keyword.isEmpty()) {
        return;
    }
    
    QProgressDialog progress("正在搜索文件...", "取消", 0, 0, this);
    progress.setWindowModality(Qt::WindowModal);
    progress.show();
    
    // 异步处理搜索 - 使用同步处理代替异步，简化问题排查
    int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
    if(sfd < 0) {
        progress.close();
        QMessageBox::critical(this, "错误", "无法连接到服务器");
        return;
    }
    
    // 登录（使用保存的凭据）
    if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
        progress.close();
        QMessageBox::critical(this, "错误", "身份验证失败");
        ::close(sfd);
        return;
    }
    
    // 搜索文件
    char result[4096] = {0};
    int n = search_files(sfd, keyword.toUtf8().constData(), result, sizeof(result)-1);
    ::close(sfd);
    
    // 处理结果
    progress.close();
    
    // 在处理前记录原始数据 - 方便调试
    qDebug() << "收到的原始搜索结果数据:" << result;
    qDebug() << "数据长度:" << n;
    
    if (n <= 0) {
        QMessageBox::information(this, "搜索结果", "没有找到匹配的文件");
        return;
    }
    
    // 简单检查JSON格式
    if (strlen(result) <= 2) {
        QMessageBox::information(this, "搜索结果", "没有找到匹配的文件");
        return;
    }
    
    // 清空表格
    fileTable->setRowCount(0);
    
    // 使用简单的字符串解析方法，避免复杂的JSON解析
    try {
        QString jsonString = QString::fromUtf8(result);
        
        // 检查是否为空数组
        if (jsonString == "[]") {
            QMessageBox::information(this, "搜索结果", "没有找到匹配的文件");
            return;
        }
        
        // 尝试解析为QJsonDocument
        QJsonParseError jsonError;
        QJsonDocument doc = QJsonDocument::fromJson(jsonString.toUtf8(), &jsonError);
        
        if (jsonError.error != QJsonParseError::NoError) {
            qDebug() << "JSON解析错误:" << jsonError.errorString();
            qDebug() << "错误位置:" << jsonError.offset;
            
            // 使用应急解析方法
            // 分割文件条目 - 适用于简单JSON
            QStringList entries;
            QString content = jsonString.mid(1, jsonString.length() - 2); // 去掉[]
            
            // 寻找每个文件条目
            QRegExp fileRegex("\\{([^{}]*)\\}");
            int pos = 0;
            while ((pos = fileRegex.indexIn(content, pos)) != -1) {
                entries << fileRegex.cap(1);
                pos += fileRegex.matchedLength();
            }
            
            fileTable->setRowCount(entries.size());
            
            for (int i = 0; i < entries.size(); i++) {
                QString entry = entries[i];
                
                // 提取属性
                QRegExp nameRegex("\"filename\":\"([^\"]*)\"");
                QRegExp timeRegex("\"upload_time\":\"([^\"]*)\"");
                QRegExp accessRegex("\"access_level\":\"([^\"]*)\"");
                
                QString fileName = nameRegex.indexIn(entry) != -1 ? nameRegex.cap(1) : "";
                QString uploadTime = timeRegex.indexIn(entry) != -1 ? timeRegex.cap(1) : "";
                QString accessLevel = accessRegex.indexIn(entry) != -1 ? accessRegex.cap(1) : "";
                
                QTableWidgetItem *nameItem = new QTableWidgetItem(fileName);
                QTableWidgetItem *timeItem = new QTableWidgetItem(uploadTime);
                QTableWidgetItem *accessItem = new QTableWidgetItem(accessLevel);
                
                fileTable->setItem(i, 0, nameItem);
                fileTable->setItem(i, 1, timeItem);
                fileTable->setItem(i, 2, accessItem);
            }
            
            mainUserLabel->setText("用户: " + currentUser + " | 搜索结果: " + keyword);
            return;
        }
        
        // 标准JSON解析方式
        if (doc.isArray()) {
            QJsonArray files = doc.array();
            int fileCount = files.size();
            
            qDebug() << "找到文件数量:" << fileCount;
            
            if (fileCount == 0) {
                QMessageBox::information(this, "搜索结果", "没有找到匹配的文件");
                return;
            }
            
            fileTable->setRowCount(fileCount);
            
            for (int i = 0; i < fileCount; i++) {
                if (!files[i].isObject()) {
                    qDebug() << "索引" << i << "不是JSON对象";
                    continue;
                }
                
                QJsonObject file = files[i].toObject();
                
                if (file.isEmpty()) {
                    qDebug() << "警告: 索引" << i << "的文件对象为空";
                    continue;
                }
                
                qDebug() << "处理文件:" << file["filename"].toString();
                
                QTableWidgetItem *nameItem = new QTableWidgetItem(file["filename"].toString());
                QTableWidgetItem *timeItem = new QTableWidgetItem(file["upload_time"].toString());
                QTableWidgetItem *accessItem = new QTableWidgetItem(file["access_level"].toString());
                
                fileTable->setItem(i, 0, nameItem);
                fileTable->setItem(i, 1, timeItem);
                fileTable->setItem(i, 2, accessItem);
            }
            
            mainUserLabel->setText("用户: " + currentUser + " | 搜索结果: " + keyword);
        } else {
            QMessageBox::critical(this, "错误", "搜索结果格式错误: 预期JSON数组");
        }
    } catch (const std::exception& e) {
        qDebug() << "异常:" << e.what();
        QMessageBox::critical(this, "错误", QString("处理搜索结果时发生异常: %1").arg(e.what()));
    } catch (...) {
        qDebug() << "未知异常";
        QMessageBox::critical(this, "错误", "处理搜索结果时发生未知异常");
    }
}

// 管理用户功能（仅管理员可用）
void MainWindow::doManageUsers() {
    if (!isAdmin) {
        QMessageBox::warning(this, "权限不足", "只有管理员才能管理用户");
        return;
    }
    
    QProgressDialog progress("正在获取用户列表...", "取消", 0, 0, this);
    progress.setWindowModality(Qt::WindowModal);
    progress.show();
    
    // 异步处理用户列表获取
    QTimer::singleShot(100, [this, &progress]() {
        int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
        if(sfd < 0) {
            progress.close();
            QMessageBox::critical(this, "错误", "无法连接到服务器");
            return;
        }
        
        // 登录（使用保存的凭据）
        if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
            progress.close();
            QMessageBox::critical(this, "错误", "身份验证失败");
            ::close(sfd);
            return;
        }
        
        // 获取用户列表
        char result[4096] = {0};
        int n = get_user_list(sfd, result, sizeof(result)-1);
        ::close(sfd);
        
        // 处理结果
        progress.close();
        if (n > 0) {
            // 创建用户管理对话框
            QDialog dialog(this);
            dialog.setWindowTitle("用户管理");
            dialog.resize(500, 400);
            
            QVBoxLayout *layout = new QVBoxLayout(&dialog);
            
            // 用户表格
            QTableWidget *userTable = new QTableWidget(&dialog);
            userTable->setColumnCount(4);
            userTable->setHorizontalHeaderLabels({"用户ID", "用户名", "注册时间", "角色"});
            userTable->setSelectionBehavior(QAbstractItemView::SelectRows);
            userTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
            userTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
            layout->addWidget(userTable);
            
            // 解析JSON响应
            QJsonDocument doc = QJsonDocument::fromJson(result);
            if (!doc.isArray()) {
                QMessageBox::critical(this, "错误", "用户列表格式错误");
                return;
            }
            
            QJsonArray users = doc.array();
            userTable->setRowCount(users.size());
            
            for (int i = 0; i < users.size(); i++) {
                QJsonObject user = users[i].toObject();
                
                QTableWidgetItem *idItem = new QTableWidgetItem(QString::number(user["user_id"].toInt()));
                QTableWidgetItem *nameItem = new QTableWidgetItem(user["username"].toString());
                QTableWidgetItem *timeItem = new QTableWidgetItem(user["register_time"].toString());
                QTableWidgetItem *roleItem = new QTableWidgetItem(user["role"].toString());
                
                userTable->setItem(i, 0, idItem);
                userTable->setItem(i, 1, nameItem);
                userTable->setItem(i, 2, timeItem);
                userTable->setItem(i, 3, roleItem);
            }
            
            // 按钮区域
            QHBoxLayout *btnLayout = new QHBoxLayout();
            
            QPushButton *changeRoleBtn = new QPushButton("修改用户角色", &dialog);
            connect(changeRoleBtn, &QPushButton::clicked, [this, userTable, &dialog]() {
                int row = userTable->currentRow();
                if (row < 0) {
                    QMessageBox::warning(this, "错误", "请先选择一个用户");
                    return;
                }
                
                QString username = userTable->item(row, 1)->text();
                QString currentRole = userTable->item(row, 3)->text();
                
                // 如果是自己，不允许修改
                if (username == currentUser) {
                    QMessageBox::warning(this, "错误", "不能修改自己的角色");
                    return;
                }
                
                // 创建角色选择对话框
                QStringList roles;
                roles << "user" << "admin";
                
                bool ok;
                QString newRole = QInputDialog::getItem(this, "修改角色", 
                                                     "选择新角色:", 
                                                     roles, 
                                                     (currentRole == "admin" ? 1 : 0), 
                                                     false, &ok);
                
                if (!ok || newRole.isEmpty() || newRole == currentRole) {
                    return;
                }
                
                // 确认修改
                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(this, "确认修改", 
                                            "确定要将用户 " + username + " 的角色修改为 " + newRole + " 吗？",
                                            QMessageBox::Yes | QMessageBox::No);
                
                if (reply != QMessageBox::Yes) {
                    return;
                }
                
                QProgressDialog progress("正在修改用户角色...", "取消", 0, 0, this);
                progress.setWindowModality(Qt::WindowModal);
                progress.show();
                
                // 异步处理角色修改
                QTimer::singleShot(100, [this, username, newRole, &progress, &dialog]() {
                    int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
                    if(sfd < 0) {
                        progress.close();
                        QMessageBox::critical(this, "错误", "无法连接到服务器");
                        return;
                    }
                    
                    // 登录（使用保存的凭据）
                    if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
                        progress.close();
                        QMessageBox::critical(this, "错误", "身份验证失败");
                        ::close(sfd);
                        return;
                    }
                    
                    // 修改用户角色
                    int result = change_user_role(sfd, username.toUtf8().constData(), newRole.toUtf8().constData());
                    ::close(sfd);
                    
                    // 处理结果
                    progress.close();
                    if (result == 0) {
                        QMessageBox::information(this, "成功", "用户角色已成功修改");
                        dialog.close(); // 关闭用户管理对话框，让用户重新打开以刷新列表
                    } else {
                        QMessageBox::critical(this, "错误", "修改用户角色失败");
                    }
                });
            });
            
            QPushButton *closeBtn = new QPushButton("关闭", &dialog);
            connect(closeBtn, &QPushButton::clicked, &dialog, &QDialog::accept);
            
            btnLayout->addWidget(changeRoleBtn);
            btnLayout->addWidget(closeBtn);
            
            layout->addLayout(btnLayout);
            
            // 显示对话框
            dialog.exec();
        } else {
            QMessageBox::critical(this, "错误", "获取用户列表失败");
        }
    });
}

// 实现doDownload函数
void MainWindow::doDownload() {
    // 获取当前选择的行
    int row = fileTable->currentRow();
    if (row < 0) {
        QMessageBox::warning(this, "错误", "请先选择要下载的文件");
        return;
    }
    
    // 获取文件名
    QString fileName = fileTable->item(row, 0)->text();
    
    // 选择保存路径
    QString savePath = QFileDialog::getSaveFileName(this, "保存文件", fileName);
    if (savePath.isEmpty()) {
        return;
    }
    
    // 执行下载
    downloadFile(fileName, savePath);
}

// 实现doLogout函数
void MainWindow::doLogout() {
    // 清空当前用户信息
    currentUser = "";
    currentPass = "";
    currentPrivKey = "";
    isAdmin = false;
    
    // 清空表格
    fileTable->setRowCount(0);
    
    // 返回登录界面
    stack->setCurrentWidget(loginWidget);
    
    QMessageBox::information(this, "退出登录", "您已成功退出登录");
}

// 处理登录结果的槽函数
void MainWindow::onLoginFinished(bool success, bool isUserAdmin, QString username) {
    if (success) {
        currentUser = username;
        this->isAdmin = isUserAdmin;
        mainUserLabel->setText("当前用户：" + username);
        stack->setCurrentWidget(mainWidget);
        refreshFiles();
    } else {
        QMessageBox::warning(this, "登录失败", "用户名或密码错误");
    }
}

// 处理上传结果的槽函数
void MainWindow::onUploadFinished(bool success, QString fileName) {
    if (success) {
        QMessageBox::information(this, "上传成功", "文件 " + fileName + " 已成功上传");
        refreshFiles();
    } else {
        QMessageBox::warning(this, "上传失败", "上传文件 " + fileName + " 时发生错误");
    }
}

// 处理下载结果的槽函数
void MainWindow::onDownloadFinished(bool success, QString fileName) {
    if (success) {
        QMessageBox::information(this, "下载成功", "文件 " + fileName + " 已成功下载");
    } else {
        QMessageBox::warning(this, "下载失败", "下载文件 " + fileName + " 时发生错误");
    }
}

// 处理文件列表接收的槽函数
void MainWindow::onFileListReceived(QString fileListJson) {
    // 添加调试输出
    qDebug() << "收到文件列表数据: " << fileListJson;
    
    // 直接处理空数组情况
    if (fileListJson == "[]" || fileListJson.trimmed().isEmpty()) {
        qDebug() << "文件列表为空数组，直接清空表格";
        fileTable->clearContents();
        fileTable->setRowCount(0);
        return;
    }
    
    // 检查JSON格式是否有效
    if (!fileListJson.startsWith("[") || !fileListJson.endsWith("]")) {
        qDebug() << "JSON格式无效: " << fileListJson;
        QMessageBox::warning(this, "错误", "文件列表数据格式不正确");
        fileTable->clearContents();
        fileTable->setRowCount(0);
        return;
    }
    
    // 解析JSON并更新表格
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(fileListJson.toUtf8(), &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        qDebug() << "JSON解析错误: " << parseError.errorString();
        qDebug() << "原始数据: " << fileListJson.left(200);
        QMessageBox::warning(this, "错误", "文件列表数据格式错误: " + parseError.errorString());
        fileTable->clearContents();
        fileTable->setRowCount(0);
        return;
    }
    
    if (!doc.isArray()) {
        qDebug() << "JSON不是数组格式";
        QMessageBox::warning(this, "错误", "获取文件列表失败: 数据格式不正确");
        fileTable->clearContents();
        fileTable->setRowCount(0);
        return;
    }
    
    // 清除旧数据
    fileTable->clearContents();
    fileTable->setRowCount(0);
    
    // 获取文件数组
    QJsonArray files = doc.array();
    
    // 如果数组为空，显示信息
    if (files.isEmpty()) {
        qDebug() << "文件列表为空";
        return;
    }
    
    try {
        // 设置表格行数
        fileTable->setRowCount(files.size());
        
        // 填充表格数据
        for (int i = 0; i < files.size(); i++) {
            if (i >= fileTable->rowCount()) {
                qDebug() << "行索引超出范围: " << i;
                break;
            }
            
            QJsonValue fileValue = files.at(i);
            if (!fileValue.isObject()) {
                qDebug() << "文件条目不是对象格式，跳过行 " << i;
                continue;
            }
            
            QJsonObject file = fileValue.toObject();
            
            if (file.isEmpty()) {
                qDebug() << "文件对象为空，跳过行 " << i;
                continue;
            }
            
            // 安全获取文件信息，防止空值或缺失字段导致崩溃
            
            // 文件名
            QString filename = file.contains("filename") ? file["filename"].toString() : "未知";
            QTableWidgetItem* nameItem = new QTableWidgetItem(filename);
            if (nameItem) fileTable->setItem(i, 0, nameItem);
            
            // 上传时间
            QString uploadTime = file.contains("upload_time") ? file["upload_time"].toString() : "未知";
            QTableWidgetItem* timeItem = new QTableWidgetItem(uploadTime);
            if (timeItem) fileTable->setItem(i, 1, timeItem);
            
            // 权限
            QString accessLevel = file.contains("access_level") ? file["access_level"].toString() : "未知";
            QTableWidgetItem* accessItem = new QTableWidgetItem(accessLevel);
            if (accessItem) fileTable->setItem(i, 2, accessItem);
        }
        
        qDebug() << "文件列表显示完成，共 " << files.size() << " 个文件";
    } catch (const std::exception& e) {
        qDebug() << "处理文件列表时发生异常: " << e.what();
        QMessageBox::warning(this, "错误", QString("处理文件列表时发生异常: %1").arg(e.what()));
    } catch (...) {
        qDebug() << "处理文件列表时发生未知异常";
        QMessageBox::warning(this, "错误", "处理文件列表时发生未知异常");
    }
}

// 处理日志接收的槽函数
void MainWindow::onLogsReceived(QString logsJson) {
    qDebug() << "接收到日志数据: " << logsJson.left(100) << (logsJson.length() > 100 ? "..." : "");
    
    // 安全检查：如果日志数据为空，显示空表格
    if (logsJson.isEmpty() || logsJson == "[]") {
        qDebug() << "日志数据为空";
        logTable->clearContents();
        logTable->setRowCount(0);
        return;
    }
    
    // 使用try-catch捕获所有可能的异常
    try {
        // 解析JSON并更新日志表格
        QJsonParseError parseError;
        QJsonDocument doc = QJsonDocument::fromJson(logsJson.toUtf8(), &parseError);
        
        if (parseError.error != QJsonParseError::NoError) {
            qDebug() << "日志JSON解析错误: " << parseError.errorString();
            qDebug() << "原始数据: " << logsJson.left(200);
            QMessageBox::warning(this, "错误", "日志数据格式错误: " + parseError.errorString());
            logTable->clearContents();
            logTable->setRowCount(0);
            return;
        }
        
        if (!doc.isArray()) {
            qDebug() << "日志JSON不是数组格式";
            QMessageBox::warning(this, "错误", "获取日志失败: 数据格式不正确");
            logTable->clearContents();
            logTable->setRowCount(0);
            return;
        }
        
        // 清除旧数据
        logTable->clearContents();
        logTable->setRowCount(0);
        
        // 获取日志数组
        QJsonArray logs = doc.array();
        
        // 如果数组为空，显示信息
        if (logs.isEmpty()) {
            qDebug() << "日志列表为空";
            return;
        }
        
        // 设置表格行数
        logTable->setRowCount(logs.size());
        
        // 填充表格数据
        for (int i = 0; i < logs.size(); i++) {
            if (i >= logTable->rowCount()) {
                qDebug() << "行索引超出范围: " << i;
                break;
            }
            
            QJsonValue logValue = logs.at(i);
            if (!logValue.isObject()) {
                qDebug() << "日志条目不是对象格式，跳过行 " << i;
                continue;
            }
            
            QJsonObject log = logValue.toObject();
            
            if (log.isEmpty()) {
                qDebug() << "日志对象为空，跳过行 " << i;
                continue;
            }
            
            // 安全获取日志信息，防止空值或缺失字段导致崩溃
            
            // 时间
            QString opTime = log.contains("op_time") ? log["op_time"].toString() : "未知";
            QTableWidgetItem* timeItem = new QTableWidgetItem(opTime);
            if (timeItem) logTable->setItem(i, 0, timeItem);
            
            // 用户
            QString username = log.contains("username") ? log["username"].toString() : "未知";
            QTableWidgetItem* userItem = new QTableWidgetItem(username);
            if (userItem) logTable->setItem(i, 1, userItem);
            
            // 操作
            QString opType = log.contains("op_type") ? log["op_type"].toString() : "未知";
            QTableWidgetItem* opItem = new QTableWidgetItem(opType);
            if (opItem) logTable->setItem(i, 2, opItem);
            
            // 文件
            QString fileName = log.contains("file_name") ? log["file_name"].toString() : "";
            QTableWidgetItem* fileItem = new QTableWidgetItem(fileName);
            if (fileItem) logTable->setItem(i, 3, fileItem);
            
            // IP
            QString ip = log.contains("ip") ? log["ip"].toString() : "";
            QTableWidgetItem* ipItem = new QTableWidgetItem(ip);
            if (ipItem) logTable->setItem(i, 4, ipItem);
        }
        
        qDebug() << "日志列表显示完成，共 " << logs.size() << " 条记录";
    } catch (const std::exception& e) {
        qDebug() << "处理日志列表时发生异常: " << e.what();
        QMessageBox::warning(this, "错误", QString("处理日志列表时发生异常: %1").arg(e.what()));
    } catch (...) {
        qDebug() << "处理日志列表时发生未知异常";
        QMessageBox::warning(this, "错误", "处理日志列表时发生未知异常");
    }
}

// 实现showRegister函数
void MainWindow::showRegister() {
    // 切换到注册界面
    stack->setCurrentWidget(registerWidget);
}

// 实现showLogin函数
void MainWindow::showLogin() {
    // 切换到登录界面
    stack->setCurrentWidget(loginWidget);
}

// 实现refreshLogs函数
void MainWindow::refreshLogs() {
    // 创建日志工作线程
    QThread* thread = new QThread;
    LogWorker* worker = new LogWorker();
    
    worker->moveToThread(thread);
    
    // 连接信号和槽
    connect(thread, &QThread::started, worker, &LogWorker::getLogs);
    connect(worker, &LogWorker::logsReceived, this, &MainWindow::onLogsReceived);
    connect(worker, &LogWorker::logsReceived, thread, &QThread::quit);
    connect(thread, &QThread::finished, worker, &QObject::deleteLater);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    
    // 启动线程
    thread->start();
}

// 实现uploadFile函数
void MainWindow::uploadFile() {
    // 调用doUpload函数
    doUpload();
}

// 实现deleteUser函数
void MainWindow::deleteUser(const QString &username) {
    // 确认删除
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "确认删除", "确定要删除用户 " + username + " 吗？\n这将同时删除该用户的所有文件！",
                                 QMessageBox::Yes | QMessageBox::No);
    
    if (reply != QMessageBox::Yes) {
        return;
    }
    
    // 创建进度对话框
    QProgressDialog progress("正在删除用户...", "取消", 0, 0, this);
    progress.setWindowModality(Qt::WindowModal);
    progress.show();
    QApplication::processEvents();
    
    // 连接到服务器
    int sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
    if (sfd < 0) {
        progress.close();
        QMessageBox::critical(this, "错误", "连接服务器失败");
        return;
    }
    
    // 登录
    if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
        progress.close();
        QMessageBox::critical(this, "错误", "身份验证失败");
        ::close(sfd);
        return;
    }
    
    // 删除用户
    qDebug() << "正在删除用户: " << username;
    int result = delete_user(sfd, username.toUtf8().constData());
    ::close(sfd);
    
    // 处理结果
    progress.close();
    if (result == 0) {
        QMessageBox::information(this, "成功", "用户 " + username + " 已成功删除");
        refreshUsers(); // 刷新用户列表
    } else {
        // 如果失败，尝试重新连接并重试一次
        qDebug() << "删除用户失败，尝试重试...";
        
        sfd = connect_to_server(getServerIP().toUtf8().constData(), 8888);
        if (sfd < 0) {
            QMessageBox::critical(this, "错误", "删除用户失败：无法连接服务器");
            return;
        }
        
        if (!login(sfd, currentUser.toUtf8().constData(), currentPass.toUtf8().constData())) {
            QMessageBox::critical(this, "错误", "删除用户失败：身份验证失败");
            ::close(sfd);
            return;
        }
        
        result = delete_user(sfd, username.toUtf8().constData());
        ::close(sfd);
        
        if (result == 0) {
            QMessageBox::information(this, "成功", "用户 " + username + " 已成功删除");
            refreshUsers(); // 刷新用户列表
        } else {
            QMessageBox::critical(this, "错误", "删除用户失败，请检查用户是否存在");
        }
    }
}

// 显示错误消息的辅助函数
void MainWindow::showErrorMessage(QString message) {
    QMessageBox::critical(this, "错误", message);
} 