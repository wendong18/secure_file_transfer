/****************************************************************************
** Meta object code from reading C++ file 'mainwindow.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.3)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "mainwindow.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'mainwindow.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.3. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_LoginWorker_t {
    QByteArrayData data[8];
    char stringdata0[73];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_LoginWorker_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_LoginWorker_t qt_meta_stringdata_LoginWorker = {
    {
QT_MOC_LITERAL(0, 0, 11), // "LoginWorker"
QT_MOC_LITERAL(1, 12, 13), // "loginFinished"
QT_MOC_LITERAL(2, 26, 0), // ""
QT_MOC_LITERAL(3, 27, 7), // "success"
QT_MOC_LITERAL(4, 35, 11), // "isUserAdmin"
QT_MOC_LITERAL(5, 47, 8), // "username"
QT_MOC_LITERAL(6, 56, 7), // "doLogin"
QT_MOC_LITERAL(7, 64, 8) // "password"

    },
    "LoginWorker\0loginFinished\0\0success\0"
    "isUserAdmin\0username\0doLogin\0password"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_LoginWorker[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       2,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    3,   24,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       6,    2,   31,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::Bool, QMetaType::Bool, QMetaType::QString,    3,    4,    5,

 // slots: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    5,    7,

       0        // eod
};

void LoginWorker::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<LoginWorker *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->loginFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3]))); break;
        case 1: _t->doLogin((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (LoginWorker::*)(bool , bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&LoginWorker::loginFinished)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject LoginWorker::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_LoginWorker.data,
    qt_meta_data_LoginWorker,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *LoginWorker::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *LoginWorker::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_LoginWorker.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int LoginWorker::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 2)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 2)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 2;
    }
    return _id;
}

// SIGNAL 0
void LoginWorker::loginFinished(bool _t1, bool _t2, QString _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
struct qt_meta_stringdata_FileWorker_t {
    QByteArrayData data[14];
    char stringdata0[156];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_FileWorker_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_FileWorker_t qt_meta_stringdata_FileWorker = {
    {
QT_MOC_LITERAL(0, 0, 10), // "FileWorker"
QT_MOC_LITERAL(1, 11, 14), // "uploadFinished"
QT_MOC_LITERAL(2, 26, 0), // ""
QT_MOC_LITERAL(3, 27, 7), // "success"
QT_MOC_LITERAL(4, 35, 8), // "fileName"
QT_MOC_LITERAL(5, 44, 16), // "downloadFinished"
QT_MOC_LITERAL(6, 61, 16), // "fileListReceived"
QT_MOC_LITERAL(7, 78, 12), // "fileListJson"
QT_MOC_LITERAL(8, 91, 10), // "uploadFile"
QT_MOC_LITERAL(9, 102, 8), // "filePath"
QT_MOC_LITERAL(10, 111, 10), // "accessType"
QT_MOC_LITERAL(11, 122, 12), // "downloadFile"
QT_MOC_LITERAL(12, 135, 8), // "savePath"
QT_MOC_LITERAL(13, 144, 11) // "getFileList"

    },
    "FileWorker\0uploadFinished\0\0success\0"
    "fileName\0downloadFinished\0fileListReceived\0"
    "fileListJson\0uploadFile\0filePath\0"
    "accessType\0downloadFile\0savePath\0"
    "getFileList"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_FileWorker[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    2,   49,    2, 0x06 /* Public */,
       5,    2,   54,    2, 0x06 /* Public */,
       6,    1,   59,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    3,   62,    2, 0x0a /* Public */,
       8,    2,   69,    2, 0x2a /* Public | MethodCloned */,
      11,    2,   74,    2, 0x0a /* Public */,
      13,    0,   79,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,    3,    4,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,    3,    4,
    QMetaType::Void, QMetaType::QString,    7,

 // slots: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::QString,    9,    4,   10,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    9,    4,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    4,   12,
    QMetaType::Void,

       0        // eod
};

void FileWorker::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<FileWorker *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->uploadFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 1: _t->downloadFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 2: _t->fileListReceived((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 3: _t->uploadFile((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3]))); break;
        case 4: _t->uploadFile((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 5: _t->downloadFile((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 6: _t->getFileList(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (FileWorker::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FileWorker::uploadFinished)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (FileWorker::*)(bool , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FileWorker::downloadFinished)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (FileWorker::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FileWorker::fileListReceived)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject FileWorker::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_FileWorker.data,
    qt_meta_data_FileWorker,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *FileWorker::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *FileWorker::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_FileWorker.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int FileWorker::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}

// SIGNAL 0
void FileWorker::uploadFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void FileWorker::downloadFinished(bool _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void FileWorker::fileListReceived(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}
struct qt_meta_stringdata_LogWorker_t {
    QByteArrayData data[5];
    char stringdata0[37];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_LogWorker_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_LogWorker_t qt_meta_stringdata_LogWorker = {
    {
QT_MOC_LITERAL(0, 0, 9), // "LogWorker"
QT_MOC_LITERAL(1, 10, 12), // "logsReceived"
QT_MOC_LITERAL(2, 23, 0), // ""
QT_MOC_LITERAL(3, 24, 4), // "logs"
QT_MOC_LITERAL(4, 29, 7) // "getLogs"

    },
    "LogWorker\0logsReceived\0\0logs\0getLogs"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_LogWorker[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       2,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   24,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    0,   27,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,

 // slots: parameters
    QMetaType::Void,

       0        // eod
};

void LogWorker::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<LogWorker *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->logsReceived((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 1: _t->getLogs(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (LogWorker::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&LogWorker::logsReceived)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject LogWorker::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_LogWorker.data,
    qt_meta_data_LogWorker,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *LogWorker::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *LogWorker::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_LogWorker.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int LogWorker::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 2)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 2)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 2;
    }
    return _id;
}

// SIGNAL 0
void LogWorker::logsReceived(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
struct qt_meta_stringdata_MainWindow_t {
    QByteArrayData data[29];
    char stringdata0[334];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_MainWindow_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_MainWindow_t qt_meta_stringdata_MainWindow = {
    {
QT_MOC_LITERAL(0, 0, 10), // "MainWindow"
QT_MOC_LITERAL(1, 11, 15), // "onLoginFinished"
QT_MOC_LITERAL(2, 27, 0), // ""
QT_MOC_LITERAL(3, 28, 7), // "success"
QT_MOC_LITERAL(4, 36, 11), // "isUserAdmin"
QT_MOC_LITERAL(5, 48, 8), // "username"
QT_MOC_LITERAL(6, 57, 16), // "onUploadFinished"
QT_MOC_LITERAL(7, 74, 8), // "fileName"
QT_MOC_LITERAL(8, 83, 18), // "onDownloadFinished"
QT_MOC_LITERAL(9, 102, 18), // "onFileListReceived"
QT_MOC_LITERAL(10, 121, 12), // "fileListJson"
QT_MOC_LITERAL(11, 134, 14), // "onLogsReceived"
QT_MOC_LITERAL(12, 149, 8), // "logsJson"
QT_MOC_LITERAL(13, 158, 7), // "doLogin"
QT_MOC_LITERAL(14, 166, 10), // "doRegister"
QT_MOC_LITERAL(15, 177, 12), // "showRegister"
QT_MOC_LITERAL(16, 190, 9), // "showLogin"
QT_MOC_LITERAL(17, 200, 8), // "showMain"
QT_MOC_LITERAL(18, 209, 8), // "viewLogs"
QT_MOC_LITERAL(19, 218, 12), // "refreshUsers"
QT_MOC_LITERAL(20, 231, 12), // "refreshFiles"
QT_MOC_LITERAL(21, 244, 11), // "refreshLogs"
QT_MOC_LITERAL(22, 256, 10), // "uploadFile"
QT_MOC_LITERAL(23, 267, 10), // "deleteFile"
QT_MOC_LITERAL(24, 278, 10), // "deleteUser"
QT_MOC_LITERAL(25, 289, 14), // "changeUserRole"
QT_MOC_LITERAL(26, 304, 4), // "role"
QT_MOC_LITERAL(27, 309, 16), // "showErrorMessage"
QT_MOC_LITERAL(28, 326, 7) // "message"

    },
    "MainWindow\0onLoginFinished\0\0success\0"
    "isUserAdmin\0username\0onUploadFinished\0"
    "fileName\0onDownloadFinished\0"
    "onFileListReceived\0fileListJson\0"
    "onLogsReceived\0logsJson\0doLogin\0"
    "doRegister\0showRegister\0showLogin\0"
    "showMain\0viewLogs\0refreshUsers\0"
    "refreshFiles\0refreshLogs\0uploadFile\0"
    "deleteFile\0deleteUser\0changeUserRole\0"
    "role\0showErrorMessage\0message"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_MainWindow[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      19,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    3,  109,    2, 0x08 /* Private */,
       6,    2,  116,    2, 0x08 /* Private */,
       8,    2,  121,    2, 0x08 /* Private */,
       9,    1,  126,    2, 0x08 /* Private */,
      11,    1,  129,    2, 0x08 /* Private */,
      13,    0,  132,    2, 0x08 /* Private */,
      14,    0,  133,    2, 0x08 /* Private */,
      15,    0,  134,    2, 0x08 /* Private */,
      16,    0,  135,    2, 0x08 /* Private */,
      17,    0,  136,    2, 0x08 /* Private */,
      18,    0,  137,    2, 0x08 /* Private */,
      19,    0,  138,    2, 0x08 /* Private */,
      20,    0,  139,    2, 0x08 /* Private */,
      21,    0,  140,    2, 0x08 /* Private */,
      22,    0,  141,    2, 0x08 /* Private */,
      23,    1,  142,    2, 0x08 /* Private */,
      24,    1,  145,    2, 0x08 /* Private */,
      25,    2,  148,    2, 0x08 /* Private */,
      27,    1,  153,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, QMetaType::Bool, QMetaType::Bool, QMetaType::QString,    3,    4,    5,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,    3,    7,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,    3,    7,
    QMetaType::Void, QMetaType::QString,   10,
    QMetaType::Void, QMetaType::QString,   12,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    7,
    QMetaType::Void, QMetaType::QString,    5,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    5,   26,
    QMetaType::Void, QMetaType::QString,   28,

       0        // eod
};

void MainWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<MainWindow *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->onLoginFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3]))); break;
        case 1: _t->onUploadFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 2: _t->onDownloadFinished((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 3: _t->onFileListReceived((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 4: _t->onLogsReceived((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 5: _t->doLogin(); break;
        case 6: _t->doRegister(); break;
        case 7: _t->showRegister(); break;
        case 8: _t->showLogin(); break;
        case 9: _t->showMain(); break;
        case 10: _t->viewLogs(); break;
        case 11: _t->refreshUsers(); break;
        case 12: _t->refreshFiles(); break;
        case 13: _t->refreshLogs(); break;
        case 14: _t->uploadFile(); break;
        case 15: _t->deleteFile((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 16: _t->deleteUser((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 17: _t->changeUserRole((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 18: _t->showErrorMessage((*reinterpret_cast< QString(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject MainWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_MainWindow.data,
    qt_meta_data_MainWindow,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *MainWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MainWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_MainWindow.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int MainWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 19)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 19;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 19)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 19;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
