#!/bin/bash
# 锁竞争压测脚本
# 使用stress-ng模拟mutex争用

set -e

DURATION="${1:-180}"
echo "=========================================="
echo " 锁竞争压测"
echo "=========================================="
echo "持续时间: ${DURATION}s"
echo ""

echo "启动mutex争用压力 (8个线程)..."
stress-ng --mutex 8 --timeout "${DURATION}s" --metrics-brief &
LOCK_PID=$!
echo "  stress-ng PID: $LOCK_PID"

echo ""
echo "压测运行中，${DURATION}s后自动停止..."
echo ""
echo "在另一个终端运行诊断工具:"
echo "  sudo python3 -m src.main --probe lock --duration ${DURATION}"
echo ""

wait $LOCK_PID 2>/dev/null
echo "压测完成。"