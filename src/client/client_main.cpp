#include <QApplication>
#include <QDebug>
#include <QMessageBox>
#include "mainwindow.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif

int main(int argc, char *argv[]) {
    // 初始化WSA (Windows平台)
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        qDebug() << "Failed to initialize Winsock";
        return 1;
    }
#endif

    // 初始化Qt应用程序
    QApplication app(argc, argv);
    
    try {
        // 设置应用程序信息
        app.setApplicationName("安全文件传输系统");
        app.setOrganizationName("安全研究组");
        
        // 创建并显示主窗口
        MainWindow mainWindow;
        mainWindow.setWindowTitle("安全文件传输系统");
        mainWindow.resize(800, 600);
        mainWindow.show();
        
        // 运行应用程序事件循环
        return app.exec();
    } catch (const std::exception& e) {
        qDebug() << "程序发生异常: " << e.what();
        QMessageBox::critical(nullptr, "错误", QString("程序发生严重错误：%1").arg(e.what()));
        return 1;
    } catch (...) {
        qDebug() << "程序发生未知异常";
        QMessageBox::critical(nullptr, "错误", "程序发生未知严重错误");
        return 1;
    }
    
    // 清理WSA (Windows平台)
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
