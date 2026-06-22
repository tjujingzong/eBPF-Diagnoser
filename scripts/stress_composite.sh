#!/bin/bash
# 组合压测脚本：同时触发多种异常场景
# 用于验证跨场景关联分析能力

set -e

DURATION="${1:-120}"
echo "=========================================="
echo " 组合压测（多场景同时触发）"
echo "=========================================="
echo "持续时间: ${DURATION}s"
echo ""

# CPU + I/O + 内存 组合
echo "[1/4] 启动CPU压力..."
stress-ng --cpu 2 --cpu-method matrixprod --timeout "${DURATION}s" --metrics-brief &
echo "  CPU压力 PID: $!"

sleep 2
echo "[2/4] 启动I/O压力..."
TEST_FILE="/tmp/fio-composite-test.img"
[[ ! -f "$TEST_FILE" ]] && dd if=/dev/zero of="$TEST_FILE" bs=1M count=2048 status=none
fio --name=composite-io --filename="$TEST_FILE" --size=2G --rw=randrw \
    --rwmixread=70 --bs=4k --iodepth=32 --numjobs=2 \
    --runtime="${DURATION}" --time_based --group_reporting > /dev/null 2>&1 &
echo "  I/O压力 PID: $!"

sleep 2
echo "[3/4] 启动内存压力..."
stress-ng --vm 2 --vm-bytes 40% --vm-keep --timeout "${DURATION}s" --metrics-brief &
echo "  内存压力 PID: $!"

sleep 2
echo "[4/4] 启动锁竞争..."
stress-ng --mutex 4 --timeout "${DURATION}s" --metrics-brief &
echo "  锁竞争 PID: $!"

echo ""
echo "所有压测已启动，运行${DURATION}秒..."
echo ""
echo "在另一个终端运行全量诊断:"
echo "  sudo python3 -m src.main --probe all --duration ${DURATION} --output all"
echo ""

# 等待所有后台进程
wait 2>/dev/null

# 清理
rm -f "$TEST_FILE" 2>/dev/null
echo "组合压测完成。"