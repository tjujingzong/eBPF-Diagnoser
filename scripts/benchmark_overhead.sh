#!/bin/bash
# 性能开销基准测试脚本
# 对比eBPF Diagnoser运行前后的系统性能变化

set -e

echo "=========================================="
echo " eBPF Diagnoser 性能开销基准测试"
echo "=========================================="

DURATION=30
RESULTS_DIR="/tmp/ebpf-diagnoser-benchmark"
mkdir -p "$RESULTS_DIR"

# 基准测试函数
run_benchmark() {
    local label="$1"
    local tool_running="$2"

    echo ""
    echo "--- $label ---"

    # CPU基准 (sysbench)
    echo "  测试CPU性能..."
    sysbench cpu --time=10 --threads=4 run 2>&1 | \
        grep "events per second" | awk '{print "  CPU: " $0}' | tee -a "$RESULTS_DIR/${label}.txt"

    # 内存基准
    echo "  测试内存性能..."
    sysbench memory --time=10 --memory-block-size=1K --memory-total-size=10G run 2>&1 | \
        grep -E "(transfer|operations)" | awk '{print "  MEM: " $0}' | tee -a "$RESULTS_DIR/${label}.txt"

    # I/O基准
    echo "  测试I/O性能..."
    fio --name=bench --filename=/tmp/fio-bench.img --size=512M --rw=randread \
        --bs=4k --iodepth=16 --numjobs=1 --runtime=10 --time_based \
        --group_reporting 2>&1 | \
        grep -E "(IOPS|lat|clat)" | head -5 | awk '{print "  IO: " $0}' | tee -a "$RESULTS_DIR/${label}.txt"

    # 记录系统开销
    if [[ "$tool_running" == "yes" ]]; then
        echo "  工具自身开销:"
        ps aux | grep "ebpf-diagnoser\|python3.*src.main" | grep -v grep | \
            awk '{printf "  PID=%s CPU=%s%% MEM=%s%% RSS=%sMB\n", $2, $3, $4, $6/1024}' | \
            tee -a "$RESULTS_DIR/${label}.txt"
    fi
}

# 1. 不运行工具的基准
echo ""
echo "=== 阶段1: 基线测量 (工具未运行) ==="
run_benchmark "baseline" "no"

# 2. 启动诊断工具
echo ""
echo "=== 阶段2: 启动eBPF Diagnoser ==="
sudo python3 -m src.main --probe all --duration 300 --output json --output-file /tmp/ebpf-diag-bench.json &
TOOL_PID=$!
echo "诊断工具PID: $TOOL_PID"
sleep 5  # 等待工具初始化

# 3. 运行工具时的基准
echo ""
echo "=== 阶段3: 工具运行中测量 ==="
run_benchmark "with_tool" "yes"

# 4. 停止工具
echo ""
echo "=== 阶段4: 停止工具 ==="
sudo kill $TOOL_PID 2>/dev/null || true
wait $TOOL_PID 2>/dev/null || true
sleep 3

# 5. 停止工具后的基准
echo ""
echo "=== 阶段5: 恢复测量 (工具已停止) ==="
run_benchmark "recovery" "no"

# 汇总对比
echo ""
echo "=========================================="
echo " 性能开销测试结果"
echo "=========================================="
echo ""
echo "基线结果:"
cat "$RESULTS_DIR/baseline.txt" 2>/dev/null || echo "  (无数据)"
echo ""
echo "工具运行中结果:"
cat "$RESULTS_DIR/with_tool.txt" 2>/dev/null || echo "  (无数据)"
echo ""
echo "恢复后结果:"
cat "$RESULTS_DIR/recovery.txt" 2>/dev/null || echo "  (无数据)"
echo ""

# 清理
rm -f /tmp/fio-bench.img /tmp/ebpf-diag-bench.json

echo "基准测试完成。详细结果保存在: $RESULTS_DIR/"