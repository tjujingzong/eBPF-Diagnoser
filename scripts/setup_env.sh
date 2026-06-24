#!/bin/bash
# eBPF Diagnoser 环境搭建脚本
# 在Ubuntu 24.04 / openKylin 中运行

set -e

echo "=========================================="
echo " eBPF Diagnoser 环境搭建"
echo "=========================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 检查是否root
if [[ $EUID -ne 0 ]]; then
    error "此脚本需要root权限运行 (sudo ./setup_env.sh)"
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 1. 系统更新
info "更新系统软件包..."
apt-get update -qq
apt-get upgrade -y -qq

# 2. 安装eBPF开发工具链
info "安装eBPF开发工具链..."
apt-get install -y -qq \
    build-essential \
    clang \
    llvm \
    llvm-dev \
    libbpf-dev \
    linux-headers-$(uname -r) \
    pkg-config

# 尝试安装BCC包 (Ubuntu可用，openKylin不可用)
if apt-cache show bpfcc-tools &>/dev/null; then
    info "安装BCC系统包..."
    apt-get install -y -qq \
        bpfcc-tools python3-bpfcc libbpfcc-dev bpftool 2>/dev/null || true
fi

# 验证BCC是否可用，不可用则从源码编译
if ! python3 -c "from bcc import BPF" 2>/dev/null; then
    warn "BCC包不可用，从源码编译..."
    apt-get install -y -qq \
        cmake flex bison libelf-dev libfl-dev liblzma-dev \
        libclang-dev git

    if [[ ! -d /tmp/bcc ]]; then
        git clone --depth=1 https://github.com/iovisor/bcc.git /tmp/bcc
    fi
    mkdir -p /tmp/bcc/build && cd /tmp/bcc/build
    cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr
    make -j$(nproc)
    make install
    echo /usr/lib64 | tee /etc/ld.so.conf.d/bcc.conf
    ldconfig
    cd "$PROJECT_DIR" 2>/dev/null || cd "$(dirname "$0")/.."
    info "BCC源码编译安装完成"
fi

# 3. 安装Python依赖
info "安装Python 3和pip..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv

# 4. 安装压测工具
info "安装压测工具..."
apt-get install -y -qq \
    fio \
    sysbench \
    hwloc \
    numactl 2>/dev/null || true

# stress-ng 在某些发行版(如openKylin)中可能存在依赖冲突
if ! command -v stress-ng &>/dev/null; then
    if apt-cache show stress-ng &>/dev/null; then
        apt-get install -y -qq stress-ng 2>/dev/null || {
            warn "stress-ng 安装失败(依赖冲突)，尝试强制安装..."
            apt-get download stress-ng 2>/dev/null && \
            dpkg --force-depends -i stress-ng_*.deb 2>/dev/null || \
            warn "stress-ng 不可用，部分测试将无法运行"
        }
    fi
fi

# 5. 验证eBPF支持
info "验证eBPF支持..."
echo ""
echo "内核版本: $(uname -r)"
echo ""

# 检查BPF syscall
if command -v bpftool &>/dev/null && bpftool feature 2>/dev/null | grep -q "bpf_syscall"; then
    info "✓ BPF syscall可用"
elif [[ -d /sys/fs/bpf ]]; then
    info "✓ BPF文件系统可用"
else
    warn "⚠ BPF syscall可能不可用"
fi

# 检查BTF支持
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    info "✓ BTF支持可用"
else
    warn "⚠ BTF不支持 (部分CO-RE功能受限)"
fi

# 检查关键tracepoint
echo ""
info "检查关键tracepoint:"
for tp in sched:sched_switch block:block_rq_issue vmscan:mm_vmscan_kswapd_wake raw_syscalls:sys_enter; do
    category="${tp%%:*}"
    event="${tp##*:}"
    if [[ -f /sys/kernel/debug/tracing/events/${category}/${event} ]]; then
        info "  ✓ $tp"
    else
        warn "  ⚠ $tp 可能不可用"
    fi
done

# 6. 创建Python虚拟环境
info "创建Python虚拟环境..."
VENV_DIR="$PROJECT_DIR/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

# 7. 安装Python包
info "安装Python依赖..."
pip install --quiet --upgrade pip
pip install --quiet pyyaml rich

# 8. 验证BCC Python绑定
info "验证BCC Python绑定..."
python3 -c "from bcc import BPF; print('✓ BCC Python绑定正常')" 2>/dev/null || \
    warn "⚠ BCC Python绑定导入失败，请检查BCC安装 (系统包或源码编译)"

echo ""
echo "=========================================="
info "环境搭建完成！"
echo "=========================================="
echo ""
echo "使用方式:"
echo "  cd $PROJECT_DIR"
echo "  source .venv/bin/activate"
echo "  sudo python3 -m src.main --probe cpu,io --duration 60"
echo ""
echo "压测验证:"
echo "  sudo bash scripts/stress_cpu.sh &"
echo "  sudo python3 -m src.main --probe cpu --duration 120"
echo ""