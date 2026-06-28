#!/bin/bash
# 一键测试脚本：验证eBPF Diagnoser的5类异常检测能力
# 在Ubuntu/openKylin VM中运行 (需root权限)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DURATION=30  # 每项测试时长
PASS=0
FAIL=0
RESULTS=()

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 优先使用 ebpf-diagnoser CLI，回退到 python -m src.main
if command -v ebpf-diagnoser &> /dev/null; then
    TOOL_CMD="sudo ebpf-diagnoser run"
else
    TOOL_CMD="sudo python3 -m src.main"
fi

run_test() {
    local test_name="$1"
    local probe="$2"
    local stress_cmd="$3"
    local check_keyword="$4"
    local threshold_args="${5:-}"

    echo ""
    echo "================================================"
    echo -e "${YELLOW}测试: $test_name${NC}"
    echo "================================================"
    echo "探针: $probe"
    echo "压测: $stress_cmd"
    echo "检测关键词: $check_keyword"
    [[ -n "$threshold_args" ]] && echo "自定义阈值: $threshold_args"
    echo ""

    # 启动压测(后台)
    eval "$stress_cmd" > /dev/null 2>&1 &
    STRESS_PID=$!
    sleep 3  # 等压测起来

    # 运行诊断工具
    OUTPUT=$($TOOL_CMD --probe "$probe" --duration "$DURATION" --output json $threshold_args 2>&1) || true

    # 停止压测
    kill $STRESS_PID 2>/dev/null || true
    wait $STRESS_PID 2>/dev/null || true

    # 检查结果
    if echo "$OUTPUT" | grep -q "$check_keyword"; then
        echo -e "${GREEN}✓ 通过${NC}: 检测到 '$check_keyword'"
        RESULTS+=("$test_name: PASS")
        PASS=$((PASS + 1))
    else
        echo -e "${RED}✗ 失败${NC}: 未检测到 '$check_keyword'"
        echo "输出摘要: $(echo "$OUTPUT" | head -20)"
        RESULTS+=("$test_name: FAIL")
        FAIL=$((FAIL + 1))
    fi
}

echo "=========================================="
echo " eBPF Diagnoser 一键测试"
echo "=========================================="
echo "项目目录: $PROJECT_DIR"
echo "每项测试时长: ${DURATION}s"
echo ""

cd "$PROJECT_DIR"

# 检查工具是否可运行
echo "检查诊断工具..."
python3 -c "from src.config import load_config; print('✓ 导入成功')" || {
    echo "❌ 导入失败，请检查PYTHONPATH"
    exit 1
}

# 测试1: CPU异常检测
run_test "CPU异常检测" "cpu" \
    "stress-ng --cpu 4 --cpu-method matrixprod --timeout ${DURATION}s" \
    "cpu_anomaly"

# 测试2: I/O异常检测 (降低P99阈值以适配高性能存储环境)
run_test "I/O异常检测" "io" \
    "fio --name=test --filename=/tmp/fio-test.img --size=1G --rw=randrw --bs=4k --iodepth=64 --numjobs=4 --runtime=${DURATION} --time_based" \
    "io_anomaly" \
    "--threshold io_p99_high=0.3"

# 测试3: 内存异常检测 (提高可用内存阈值并加大压力以适配大swap VM)
run_test "内存异常检测" "mem" \
    "stress-ng --vm 4 --vm-bytes 95% --vm-keep --timeout ${DURATION}s" \
    "memory_anomaly" \
    "--threshold mem_available_low=60"

# 测试4: 锁竞争检测
run_test "锁竞争检测" "lock" \
    "stress-ng --mutex 8 --timeout ${DURATION}s" \
    "lock_anomaly"

# 测试5: 系统调用异常检测
run_test "系统调用异常检测" "syscall" \
    "stress-ng --pid 8 --timeout ${DURATION}s" \
    "syscall_anomaly"

# 测试6: JSON输出格式
echo ""
echo "================================================"
echo -e "${YELLOW}测试: JSON输出格式完整性${NC}"
echo "================================================"
stress-ng --cpu 4 --cpu-method matrixprod --timeout ${DURATION}s > /dev/null 2>&1 &
STRESS_PID=$!
sleep 3
OUTPUT=$($TOOL_CMD --probe cpu --duration 20 --output json 2>&1) || true
kill $STRESS_PID 2>/dev/null || true
wait $STRESS_PID 2>/dev/null || true
REQUIRED_FIELDS=("type" "affected_objects" "key_metrics" "time_window" "root_cause" "evidence_chain" "recommendations")
MISSING=()
for field in "${REQUIRED_FIELDS[@]}"; do
    if ! echo "$OUTPUT" | grep -q "$field"; then
        MISSING+=("$field")
    fi
done

if [[ ${#MISSING[@]} -eq 0 ]]; then
    echo -e "${GREEN}✓ 通过${NC}: 所有必需字段都存在"
    RESULTS+=("JSON输出格式: PASS")
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ 失败${NC}: 缺少字段: ${MISSING[*]}"
    RESULTS+=("JSON输出格式: FAIL")
    FAIL=$((FAIL + 1))
fi

# 测试7: 多探针同时运行
echo ""
echo "================================================"
echo -e "${YELLOW}测试: 多探针协同运行${NC}"
echo "================================================"
stress-ng --cpu 2 --vm 2 --vm-bytes 30% --timeout ${DURATION}s > /dev/null 2>&1 &
STRESS_PID=$!
sleep 3
OUTPUT=$($TOOL_CMD --probe cpu,mem --duration 10 --output json 2>&1) || true
kill $STRESS_PID 2>/dev/null || true
wait $STRESS_PID 2>/dev/null || true

if echo "$OUTPUT" | grep -q "anomal"; then
    echo -e "${GREEN}✓ 通过${NC}: 多探针协同正常"
    RESULTS+=("多探针协同: PASS")
    PASS=$((PASS + 1))
else
    echo -e "${RED}✗ 失败${NC}: 多探针协同异常"
    RESULTS+=("多探针协同: FAIL")
    FAIL=$((FAIL + 1))
fi

# 汇总
echo ""
echo "=========================================="
echo " 测试结果汇总"
echo "=========================================="
for result in "${RESULTS[@]}"; do
    echo "  $result"
done
echo ""
echo -e "通过: ${GREEN}${PASS}${NC}  失败: ${RED}${FAIL}${NC}  总计: $((PASS + FAIL))"
echo ""

# 清理
rm -f /tmp/fio-test.img /tmp/fio-composite-test.img 2>/dev/null

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}所有测试通过！${NC}"
    exit 0
else
    echo -e "${RED}部分测试失败，请检查上方输出。${NC}"
    exit 1
fi