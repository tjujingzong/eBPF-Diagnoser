#!/bin/bash
# eBPF Diagnoser 环境搭建脚本 (libbpf + CO-RE)
# 在Ubuntu 24.04 / openKylin / Fedora 中运行

set -e

echo "=========================================="
echo " eBPF Diagnoser 环境搭建 (libbpf)"
echo "=========================================="

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    error "此脚本需要root权限运行 (sudo ./setup_env.sh)"
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 检测发行版
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}
DISTRO=$(detect_distro)
info "检测到发行版: $DISTRO"

# 1. 安装运行时依赖
info "安装运行时依赖..."
case "$DISTRO" in
    ubuntu|debian|linuxmint|openkylin)
        apt-get update -qq
        apt-get install -y -qq \
            python3 python3-pip python3-venv \
            libbpf-dev libelf1 zlib1g \
            linux-headers-"$(uname -r)" \
            bpftool
        ;;
    fedora)
        dnf install -y \
            python3 python3-pip \
            libbpf elfutils-libelf zlib \
            kernel-headers kernel-devel \
            bpftool
        ;;
    rhel|centos|rocky|almalinux)
        dnf install -y epel-release 2>/dev/null || true
        dnf install -y \
            python3 python3-pip \
            libbpf elfutils-libelf zlib \
            kernel-headers kernel-devel \
            bpftool
        ;;
    *)
        warn "未知发行版，请手动安装: libbpf, libelf, zlib, python3, bpftool"
        ;;
esac

# 2. 安装开发工具链 (用于编译BPF程序和loader)
info "安装开发工具链..."
case "$DISTRO" in
    ubuntu|debian|linuxmint|openkylin)
        apt-get install -y -qq \
            build-essential clang llvm pkg-config
        ;;
    fedora|rhel|centos|rocky|almalinux)
        dnf install -y gcc clang llvm pkgconf-pkg-config make
        ;;
esac

# 3. 安装Python依赖
info "安装Python依赖..."
pip3 install --quiet --break-system-packages pyyaml rich 2>/dev/null \
    || pip3 install --quiet pyyaml rich 2>/dev/null \
    || pip install --quiet pyyaml rich

# 4. 安装压测工具
info "安装压测工具..."
case "$DISTRO" in
    ubuntu|debian|linuxmint|openkylin)
        apt-get install -y -qq \
            fio sysbench hwloc numactl 2>/dev/null || true
        if ! command -v stress-ng &>/dev/null; then
            apt-get install -y -qq stress-ng 2>/dev/null || \
                warn "stress-ng 不可用，部分测试将无法运行"
        fi
        ;;
    fedora|rhel|centos|rocky|almalinux)
        dnf install -y fio stress-ng hwloc numactl 2>/dev/null || true
        ;;
esac

# 5. 编译BPF程序和loader
info "编译BPF程序和loader..."
cd "$PROJECT_DIR"
make clean && make all

# 6. 验证eBPF支持
info "验证eBPF支持..."
echo ""
echo "内核版本: $(uname -r)"
echo ""

if [[ -f /sys/kernel/btf/vmlinux ]]; then
    info "✓ BTF支持可用 (CO-RE可工作)"
else
    warn "⚠ BTF不支持 — CO-RE 需要内核 5.2+ 且 CONFIG_DEBUG_INFO_BTF=y"
fi

if [[ -d /sys/fs/bpf ]]; then
    info "✓ BPF文件系统可用"
else
    warn "⚠ BPF文件系统不可用"
fi

echo ""
info "检查关键tracepoint:"
for tp in sched:sched_switch block:block_rq_issue vmscan:mm_vmscan_kswapd_wake raw_syscalls:sys_enter syscalls:sys_enter_futex; do
    category="${tp%%:*}"
    event="${tp##*:}"
    if [[ -f /sys/kernel/debug/tracing/events/${category}/${event} ]]; then
        info "  ✓ $tp"
    else
        warn "  ⚠ $tp 可能不可用"
    fi
done

# 7. 验证编译产物
echo ""
info "验证编译产物:"
for obj in build/bpf/*.bpf.o; do
    if [[ -f "$obj" ]]; then
        info "  ✓ $(basename $obj)"
    fi
done
if [[ -x build/bin/bpf_loader ]]; then
    info "  ✓ bpf_loader"
else
    warn "  ⚠ bpf_loader 未找到"
fi

echo ""
echo "=========================================="
info "环境搭建完成！"
echo "=========================================="
echo ""
echo "开发模式运行:"
echo "  cd $PROJECT_DIR"
echo "  sudo python3 -m src.main --probe all --duration 60"
echo ""
echo "构建一键安装包:"
echo "  bash scripts/build_installer.sh"
echo "  sudo bash dist/ebpf-diagnoser-*.sh"
echo ""
