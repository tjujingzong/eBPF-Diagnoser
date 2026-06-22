#!/bin/bash
# I/O延迟抖动压测脚本
# 使用fio模拟随机读写压力

set -e

DURATION="${1:-180}"
echo "=========================================="
echo " I/O延迟抖动压测"
echo "=========================================="
echo "持续时间: ${DURATION}s"
echo ""

# 创建测试文件
TEST_FILE="/tmp/fio-test.img"
if [[ ! -f "$TEST_FILE" ]]; then
    echo "创建4G测试文件..."
    dd if=/dev/zero of="$TEST_FILE" bs=1M count=4096 status=progress
fi

echo "启动随机读写压力..."
fio --name=randrw-test \
    --filename="$TEST_FILE" \
    --size=4G \
    --rw=randrw \
    --rwmixread=70 \
    --bs=4k \
    --iodepth=64 \
    --numjobs=4 \
    --runtime="${DURATION}" \
    --time_based \
    --group_reporting

echo ""
echo "清理测试文件..."
rm -f "$TEST_FILE"
echo "压测完成。"