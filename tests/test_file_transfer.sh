#!/bin/bash

# 生成测试文件
echo "hello world" > tests/sample.txt

# 启动 server
./server & PID=$!; sleep 1

# 注册+登录（app 里用的是 u3/p3）
echo -e "u3\np3\nu3\np3" | ./app

# 上传
echo "[TEST] 上传 sample.txt"
./client_upload u3 p3 tests/sample.txt sample.txt

# 下载
echo "[TEST] 下载 sample.txt"
./client_download u3 p3 sample.txt down.txt

# 校验
if diff tests/sample.txt down.txt; then
    echo "[PASS] 文件上传下载一致"
    kill $PID; exit 0
else
    echo "[FAIL] 文件内容不一致"
    kill $PID; exit 1
fi
#
