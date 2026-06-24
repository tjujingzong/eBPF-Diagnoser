#!/bin/bash
# eBPF Diagnoser Self-Extracting Installer
# Usage: sudo bash ebpf-diagnoser-VERSION-ARCH.sh

set -e

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

INSTALL_DIR="/opt/ebpf-diagnoser"
BIN_LINK="/usr/local/bin/ebpf-diagnoser"

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    error "请使用 sudo 运行此安装脚本"
fi

# --- Detect distro ---
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

DISTRO=$(detect_distro)
info "检测到发行版: $DISTRO"

# --- Install runtime dependencies per distro ---
install_deps() {
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
        opensuse*|sles)
            zypper install -y \
                python3 python3-pip \
                libbpf1 libelf1 zlib \
                kernel-devel \
                bpftool
            ;;
        *)
            warn "未知发行版 '$DISTRO'，检查必要依赖..."
            for lib in libbpf libelf; do
                ldconfig -p | grep -q "$lib" || error "缺少库: $lib"
            done
            command -v python3 >/dev/null || error "未找到 python3"
            ;;
    esac
}

info "安装运行时依赖..."
install_deps

# --- Install Python packages ---
info "安装Python依赖..."
pip3 install --quiet --break-system-packages pyyaml rich 2>/dev/null \
    || pip3 install --quiet pyyaml rich 2>/dev/null \
    || pip install --quiet pyyaml rich

# --- Check kernel BPF support ---
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    warn "未检测到 BTF (/sys/kernel/btf/vmlinux)。CO-RE 可能无法工作。"
    warn "需要内核 5.2+ 并启用 CONFIG_DEBUG_INFO_BTF=y。"
fi

if ! grep -q "CONFIG_BPF_SYSCALL=y" /boot/config-"$(uname -r)" 2>/dev/null; then
    warn "无法确认 CONFIG_BPF_SYSCALL 是否启用"
fi

# --- Extract payload ---
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
info "解压安装包..."

ARCHIVE_LINE=$(awk '/^__PAYLOAD__$/{print NR + 1; exit 0;}' "$0")
tail -n +"$ARCHIVE_LINE" "$0" | tar xz -C "$TMPDIR"

# --- Install files ---
info "安装到 $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -r "$TMPDIR/ebpf-diagnoser/"* "$INSTALL_DIR/"

# --- Create CLI wrapper ---
cat > "$BIN_LINK" << 'WRAPPER'
#!/bin/bash
exec python3 /opt/ebpf-diagnoser/src/main.py "$@"
WRAPPER
chmod +x "$BIN_LINK"

# --- Cleanup ---
info ""
info "========================================"
info " eBPF Diagnoser 安装成功!"
info "========================================"
info ""
info "使用方法:"
info "  sudo ebpf-diagnoser --probe all"
info "  sudo ebpf-diagnoser --probe cpu,io --duration 60"
info "  sudo ebpf-diagnoser --output md"
info ""
info "卸载方法:"
info "  sudo rm -rf $INSTALL_DIR $BIN_LINK"
info ""

exit 0

__PAYLOAD__
