#!/bin/bash
# openKylin 后安装配置脚本
# 在openKylin安装完成并启动后，通过SSH或控制台运行此脚本
# 配置SSH、eBPF开发环境、压测工具等
#
# 使用方式 (在openKylin VM内运行):
#   sudo bash scripts/postinstall-openkylin.sh
#
# 或从Windows通过SSH:
#   ssh kylin 'sudo bash -s' < scripts/postinstall-openkylin.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    error "此脚本需要root权限，请使用sudo运行"
fi

step "=========================================="
step "  openKylin eBPF开发环境配置"
step "=========================================="

# 1. 系统更新
step "更新系统..."
apt-get update -qq 2>/dev/null || yum update -y 2>/dev/null || true
apt-get upgrade -y -qq 2>/dev/null || true

# 2. 安装SSH服务
step "配置SSH服务..."
if command -v apt-get &>/dev/null; then
    apt-get install -y openssh-server 2>/dev/null || true
elif command -v dnf &>/dev/null; then
    dnf install -y openssh-server 2>/dev/null || true
fi

# 配置SSH允许密码登录和密钥登录
mkdir -p /etc/ssh
cat >> /etc/ssh/sshd_config << 'EOF'
# VM SSH 配置
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# 配置用户SSH目录
USER_HOME="/home/ljz"
mkdir -p "${USER_HOME}/.ssh"
chmod 700 "${USER_HOME}/.ssh"
chown -R ljz:ljz "${USER_HOME}/.ssh" 2>/dev/null || true

# 3. 安装eBPF开发工具链
step "安装eBPF开发工具链..."

# openKylin 2.0 基于Debian，使用apt
if command -v apt-get &>/dev/null; then
    info "使用apt安装eBPF工具..."

    # 安装编译工具链
    apt-get install -y \
        build-essential clang llvm llvm-dev \
        libbpf-dev linux-headers-$(uname -r) \
        bpftool pkg-config \
        2>/dev/null || warn "部分eBPF包安装失败，尝试其他方式..."

    # 安装BCC (eBPF Python绑定)
    apt-get install -y \
        bpfcc-tools python3-bpfcc libbpfcc-dev \
        2>/dev/null || warn "BCC包安装失败，将尝试源码安装..."

    # 如果BCC包不存在，从源码安装
    if ! dpkg -l python3-bpfcc &>/dev/null; then
        warn "BCC包不可用，从源码安装..."
        apt-get install -y \
            git cmake python3-dev flex bison \
            libclang-dev libelf-dev libfl-dev \
            liblzma-dev libpolly-17-dev \
            2>/dev/null || true

        if command -v git &>/dev/null; then
            cd /tmp
            git clone --depth=1 https://github.com/iovisor/bcc.git 2>/dev/null || true
            if [[ -d /tmp/bcc ]]; then
                mkdir -p /tmp/bcc/build && cd /tmp/bcc/build
                cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr 2>/dev/null || true
                make -j$(nproc) 2>/dev/null || true
                make install 2>/dev/null || true
                echo /usr/lib64 | tee /etc/ld.so.conf.d/bcc.conf 2>/dev/null
                ldconfig 2>/dev/null || true
                info "BCC源码安装完成(可能有警告)"
            fi
        fi
    fi

elif command -v dnf &>/dev/null; then
    info "使用dnf安装eBPF工具..."
    dnf install -y \
        clang llvm llvm-devel \
        libbpf-devel kernel-devel-$(uname -r) \
        bpfcc-tools python3-bpfcc \
        bpftool pkg-config \
        2>/dev/null || warn "部分eBPF包安装失败..."
fi

# 4. 安装Python环境
step "安装Python和工具..."
if command -v apt-get &>/dev/null; then
    apt-get install -y \
        python3 python3-pip python3-dev python3-venv \
        2>/dev/null || true
elif command -v dnf &>/dev/null; then
    dnf install -y python3 python3-pip python3-devel \
        2>/dev/null || true
fi

# 5. 安装压测工具
step "安装压测工具..."
if command -v apt-get &>/dev/null; then
    apt-get install -y \
        stress-ng fio sysbench \
        hwloc numactl \
        2>/dev/null || warn "部分压测工具安装失败..."
elif command -v dnf &>/dev/null; then
    dnf install -y stress-ng fio sysbench \
        perf hwloc numactl \
        2>/dev/null || warn "部分压测工具安装失败..."
fi

# 6. 安装其他实用工具
step "安装其他工具..."
if command -v apt-get &>/dev/null; then
    apt-get install -y \
        curl wget git vim htop tmux \
        2>/dev/null || true
fi

# 7. 验证eBPF支持
step "验证eBPF支持..."
echo ""
echo "内核版本: $(uname -r)"
echo ""

# BTF
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    info "✓ BTF支持: 可用"
else
    warn "⚠ BTF支持: 不可用 (CO-RE功能受限)"
fi

# BPF syscall
if bpftool feature 2>/dev/null | grep -q "bpf_syscall"; then
    info "✓ BPF syscall: 可用"
else
    warn "⚠ BPF syscall: 可能不可用"
fi

# 关键tracepoint
echo ""
info "检查关键tracepoint:"
for tp in "sched:sched_switch" "block:block_rq_issue" "block:block_rq_complete" \
          "vmscan:mm_vmscan_kswapd_wake" "vmscan:mm_vmscan_direct_reclaim_begin" \
          "raw_syscalls:sys_enter" "raw_syscalls:sys_exit" \
          "syscalls:sys_enter_futex" "syscalls:sys_exit_futex" \
          "kmem:mm_page_alloc" "exceptions:page_fault_user"; do
    category="${tp%%:*}"
    event="${tp##*:}"
    if [[ -f "/sys/kernel/debug/tracing/events/${category}/${event}" ]]; then
        info "  ✓ ${tp}"
    else
        # 尝试通过bpftool检查
        if bpftool show tracing 2>/dev/null | grep -q "${tp}"; then
            info "  ✓ ${tp}"
        else
            warn "  ⚠ ${tp} 可能不可用"
        fi
    fi
done

# BCC Python绑定
echo ""
python3 -c "from bcc import BPF; print('✓ BCC Python绑定正常')" 2>/dev/null || \
    warn "⚠ BCC Python绑定导入失败"

# bpftool
echo ""
if command -v bpftool &>/dev/null; then
    info "✓ bpftool: $(bpftool version 2>/dev/null | head -1)"
else
    warn "⚠ bpftool未安装"
fi

# 8. 创建Python虚拟环境
step "配置Python虚拟环境..."
USER_HOME="/home/ljz"
VENV_DIR="${USER_HOME}/ebpf-venv"

if [[ ! -d "$VENV_DIR" ]]; then
    su - ljz -c "python3 -m venv ${VENV_DIR}" 2>/dev/null || \
        python3 -m venv "$VENV_DIR"
fi

su - ljz -c "source ${VENV_DIR}/bin/activate && pip install --quiet --upgrade pip pyyaml rich" 2>/dev/null || \
    (source "${VENV_DIR}/bin/activate" && pip install --quiet --upgrade pip pyyaml rich)

chown -R ljz:ljz "$VENV_DIR" 2>/dev/null || true

echo ""
echo "============================================"
info "openKylin eBPF开发环境配置完成！"
echo "============================================"
echo ""
echo "环境信息:"
echo "  内核版本: $(uname -r)"
echo "  架构: $(uname -m)"
echo "  Python: $(python3 --version 2>/dev/null)"
echo "  BCC: $(python3 -c 'import bcc; print(bcc.__version__)' 2>/dev/null || echo 'N/A')"
echo "  bpftool: $(bpftool version 2>/dev/null | head -1 || echo 'N/A')"
echo "  stress-ng: $(stress-ng --version 2>/dev/null | head -1 || echo 'N/A')"
echo "  fio: $(fio --version 2>/dev/null | head -1 || echo 'N/A')"
echo ""
echo "下一步:"
echo "  1. 从Windows SSH连接: ssh kylin"
echo "  2. 传输项目代码: scp -r . kylin:~/ebpf-diagnoser/"
echo "  3. 进入项目目录运行诊断工具"
echo ""