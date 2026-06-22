#!/bin/bash
# CPU异常压测脚本
# 使用stress-ng模拟CPU密集型负载

set -e

DURATION="${1:-180}"
CPU_CORES="${2:-$(nproc)}"

echo "=========================================="
echo " CPU异常压测"
echo "=========================================="
echo "持续时间: ${DURATION}s"
echo "CPU核心数: ${CPU_CORES}"
echo ""

echo "[1/3] 启动CPU密集型计算 (busy loop)..."
stress-ng --cpu "$CPU_CORES" --cpu-method matrixprod --timeout "${DURATION}s" --metrics-brief &
CPU_PID=$!
echo "  stress-ng PID: $CPU_PID"

echo "[2/3] 等待5秒后启动线程竞争..."
sleep 5
# 额外的上下文切换压力
stress-ng --cpu 2 --cpu-method prime --timeout "${DURATION}s" &
CTX_PID=$!
echo "  上下文切换压力 PID: $CTX_PID"

echo "[3/3] 压测运行中，${DURATION}秒后自动停止..."
echo ""
echo "在另一个终端运行诊断工具:"
echo "  sudo python3 -m src.main --probe cpu --duration ${DURATION}"
echo ""

wait $CPU_PID $CTX_PID 2>/dev/null
echo "压测完成。"