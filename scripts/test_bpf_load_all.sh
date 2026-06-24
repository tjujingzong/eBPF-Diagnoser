#!/bin/bash
# Test all BPF probes loading with CO-RE fix
# Run: sudo bash scripts/test_bpf_load_all.sh

set -e
cd "$(dirname "$0")/.."

echo "=========================================="
echo "  BPF CO-RE Load Test"
echo "=========================================="

PASS=0
FAIL=0

for probe in cpu_probe io_probe lock_probe mem_probe syscall_probe; do
    echo ""
    echo "--- Testing $probe ---"
    OBJ="bpf/${probe}.bpf.o"
    if [ ! -f "$OBJ" ]; then
        echo "SKIP: $OBJ not found"
        continue
    fi

    echo "{\"id\":1,\"cmd\":\"LOAD\",\"probe\":\"${probe%%_probe}\",\"obj_path\":\"$OBJ\"}" | \
        timeout 5 bpf/loader/bpf_loader 2>&1 | while IFS= read -r line; do
            echo "  $line"
            if echo "$line" | grep -q '"ok":true'; then
                echo "  PASS"
            elif echo "$line" | grep -q '"ok":false'; then
                echo "  FAIL"
            fi
        done
done

echo ""
echo "=========================================="
echo "  Full Diagnoser Test"
echo "=========================================="
echo ""
echo "Running: python3 src/main.py --probe cpu --duration 5 --output json"
timeout 30 python3 src/main.py --probe cpu --duration 5 --output json 2>&1 | tail -20

echo ""
echo "Done."
