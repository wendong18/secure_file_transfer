!/bin/bash
# 启动服务端
./server &
PID=$!
sleep 1
# 用第一阶段 app 注册用户:
echo -e "sock\npass\nsock\npass" | ./app
# 测试 Socket 登录
OUT=$(echo -e "sock\npass" | ./client)
kill $PID
if [[ "$OUT" =~ "登录成功" ]]; then
  echo "Socket 测试通过"
  exit 0
else
  echo "Socket 测试失败"
  exit 1
fi
