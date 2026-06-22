#!/bin/bash
# 高频/高耗时系统调用压测脚本
# 使用多种方式模拟系统调用热点

set -e

DURATION="${1:-180}"
echo "=========================================="
echo " 系统调用异常压测"
echo "=========================================="
echo "持续时间: ${DURATION}s"
echo ""

# 1. 高频getpid调用 (轮询型)
echo "[1/3] 启动高频系统调用 (getpid轮询)..."
python3 -c "
import os, time
end = time.time() + $DURATION
count = 0
while time.time() < end:
    for _ in range(10000):
        os.getpid()
    count += 10000
    time.sleep(0.01)
print(f'getpid调用次数: {count}')
" &
SYSCALL_PID1=$!
echo "  高频getpid PID: $SYSCALL_PID1"

# 2. 高频文件stat调用
echo "[2/3] 启动高频stat调用..."
python3 -c "
import os, time
end = time.time() + $DURATION
count = 0
while time.time() < end:
    for _ in range(1000):
        try:
            os.stat('/proc/self/status')
        except:
            pass
    count += 1000
    time.sleep(0.01)
print(f'stat调用次数: {count}')
" &
SYSCALL_PID2=$!
echo "  高频stat PID: $SYSCALL_PID2"

# 3. 阻塞型系统调用 (模拟慢I/O)
echo "[3/3] 启动阻塞型read调用..."
python3 -c "
import os, time, select
end = time.time() + $DURATION
count = 0
# 创建空pipe，read会阻塞然后超时
r, w = os.pipe()
while time.time() < end:
    # 用select实现带超时的read(慢syscall)
    try:
        ready = select.select([r], [], [], 0.1)
        if ready[0]:
            os.read(r, 4096)
    except:
        pass
    count += 1
os.close(r)
os.close(w)
print(f'阻塞型调用次数: {count}')
" &
SYSCALL_PID3=$!
echo "  阻塞型read PID: $SYSCALL_PID3"

echo ""
echo "压测运行中，${DURATION}s后自动停止..."
echo ""
echo "在另一个终端运行诊断工具:"
echo "  sudo python3 -m src.main --probe syscall --duration ${DURATION}"
echo ""

wait $SYSCALL_PID1 $SYSCALL_PID2 $SYSCALL_PID3 2>/dev/null
echo "压测完成。"