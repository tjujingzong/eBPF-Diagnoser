#!/bin/bash
# 内存抖动/OOM压测脚本
# 使用stress-ng模拟内存压力

set -e

DURATION="${1:-180}"
echo "=========================================="
echo " 内存抖动/OOM压测"
echo "=========================================="
echo "持续时间: ${DURATION}s"
echo ""

echo "[1/2] 启动内存压力 (80%内存)..."
stress-ng --vm 4 --vm-bytes 80% --vm-keep --timeout "${DURATION}s" --metrics-brief &
VM_PID=$!
echo "  stress-ng PID: $VM_PID"

echo "[2/2] 等待10秒后增加内存分配/释放压力..."
sleep 10
# 额外的内存抖动（频繁分配释放）
stress-ng --vm 2 --vm-bytes 25% --timeout "${DURATION}s" --metrics-brief &
FLUX_PID=$!
echo "  内存抖动 PID: $FLUX_PID"

echo ""
echo "压测运行中，${DURATION}秒后自动停止..."
echo ""
echo "在另一个终端运行诊断工具:"
echo "  sudo python3 -m src.main --probe mem --duration ${DURATION}"
echo ""

wait $VM_PID $FLUX_PID 2>/dev/null
echo "压测完成。"