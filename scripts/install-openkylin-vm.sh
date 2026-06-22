#!/bin/bash
# openKylin QEMU 安装脚本
# 从ISO安装openKylin到qcow2磁盘镜像，供Lima使用
#
# 前提:
#   1. 已下载 openKylin Desktop ISO (ARM64)
#   2. 已安装 QEMU (brew install qemu)
#
# 使用方式:
#   bash scripts/install-openkylin-vm.sh
#
# 安装完成后:
#   1. limactl start docker/lima-openkylin.yaml
#   2. limactl shell openkylin

set -e

# ============================================================
# 配置
# ============================================================
VM_NAME="openkylin"
VM_DIR="$HOME/.lima/${VM_NAME}"
ISO_PATH="${ISO_PATH:-$HOME/Downloads/openKylin-Desktop-V2.0-SP2-arm64.iso}"
DISK_SIZE="50G"
DISK_IMAGE="${VM_DIR}/${VM_NAME}.qcow2"
MEMORY="8G"
CPUS="4"
ARCH="aarch64"

# QEMU binaries
QEMU_SYSTEM="qemu-system-aarch64"
QEMU_IMG="qemu-img"

# ============================================================
# 颜色输出
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# ============================================================
# 前置检查
# ============================================================
step "检查前置条件..."

command -v "$QEMU_SYSTEM" &>/dev/null || error "QEMU未安装，请运行: brew install qemu"
command -v "$QEMU_IMG" &>/dev/null || error "qemu-img未安装"

if [[ ! -f "$ISO_PATH" ]]; then
    error "ISO文件不存在: $ISO_PATH
请先下载openKylin ISO:
  curl -L -o ~/Downloads/openKylin-Desktop-V2.0-SP2-arm64.iso \\
    'https://mirrors.aliyun.com/openkylin-cdimage/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-arm64.iso'
或设置ISO_PATH环境变量指定ISO位置"
fi

info "ISO文件: $ISO_PATH ($(du -h "$ISO_PATH" | cut -f1))"

# ============================================================
# 创建VM目录和磁盘
# ============================================================
step "创建VM目录..."
mkdir -p "$VM_DIR"

if [[ -f "$DISK_IMAGE" ]]; then
    warn "磁盘镜像已存在: $DISK_IMAGE"
    read -p "是否删除并重新创建? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$DISK_IMAGE"
    else
        error "用户取消"
    fi
fi

step "创建qcow2磁盘镜像 (${DISK_SIZE})..."
"$QEMU_IMG" create -f qcow2 "$DISK_IMAGE" "$DISK_SIZE"
info "磁盘镜像已创建: $DISK_IMAGE"

# ============================================================
# 获取QEMU EFI固件
# ============================================================
step "查找UEFI固件..."

# macOS上QEMU的EFI固件路径
EFI_FIRMWARE=""
for path in \
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd" \
    "/usr/local/share/qemu/edk2-aarch64-code.fd" \
    "/opt/homebrew/Cellar/qemu/*/share/qemu/edk2-aarch64-code.fd" \
    "/usr/local/Cellar/qemu/*/share/qemu/edk2-aarch64-code.fd"; do
    if [[ -f "$path" ]]; then
        EFI_FIRMWARE="$path"
        break
    fi
done

if [[ -z "$EFI_FIRMWARE" ]]; then
    warn "未找到预编译的EFI固件，尝试使用pflash模式..."

    # 创建pflash卷
    PFLASH_DIR="${VM_DIR}/pflash"
    mkdir -p "$PFLASH_DIR"

    # 检查是否有share/qemu下的固件
    for base in /opt/homebrew /usr/local; do
        CODE_FD="${base}/share/qemu/edk2-aarch64-code.fd"
        VARS_FD="${base}/share/qemu/edk2-aarch64-vars.fd"
        if [[ -f "$CODE_FD" ]]; then
            EFI_FIRMWARE="$CODE_FD"
            cp "$VARS_FD" "${PFLASH_DIR}/vars.fd" 2>/dev/null || true
            info "找到EFI固件: $CODE_FD"
            break
        fi
    done

    if [[ -z "$EFI_FIRMWARE" ]]; then
        error "未找到AArch64 UEFI固件。
请确认QEMU安装完整: brew reinstall qemu
expected files in /opt/homebrew/share/qemu/edk2-aarch64-code.fd"
    fi
fi

info "EFI固件: $EFI_FIRMWARE"

# ============================================================
# 生成SSH密钥（供Lima使用）
# ============================================================
step "准备SSH密钥..."
LIMA_SSH_DIR="$HOME/.lima/_ssh"
mkdir -p "$LIMA_SSH_DIR"
if [[ ! -f "$LIMA_SSH_DIR/lima" ]]; then
    ssh-keygen -t ed25519 -f "$LIMA_SSH_DIR/lima" -N "" -C "lima-openkylin" 2>/dev/null
    info "SSH密钥已生成"
else
    info "SSH密钥已存在"
fi
PUB_KEY=$(cat "$LIMA_SSH_DIR/lima.pub")

# ============================================================
# 启动QEMU安装
# ============================================================
step "=========================================="
step "  启动openKylin安装"
step "=========================================="
step ""
step "重要提示:"
step "  1. QEMU窗口将打开openKylin安装界面"
step "  2. 在安装程序中完成分区和用户设置"
step "  3. 建议创建用户: ljz / 密码: lima"
step "  4. 安装完成后关机"
step "  5. 安装完成后运行本脚本的 --post-install 阶段"
step ""

# 创建QEMU启动脚本
INSTALL_SCRIPT="${VM_DIR}/qemu-install.sh"
cat > "$INSTALL_SCRIPT" << 'QEMU_SCRIPT'
#!/bin/bash
# QEMU安装openKylin - 由install-openkylin-vm.sh生成
set -e

VM_DIR="__VM_DIR__"
DISK_IMAGE="__DISK_IMAGE__"
ISO_PATH="__ISO_PATH__"
EFI_FIRMWARE="__EFI_FIRMWARE__"
MEMORY="__MEMORY__"
CPUS="__CPUS__"
PUB_KEY="__PUB_KEY__"

# 启动QEMU，挂载ISO和磁盘
qemu-system-aarch64 \
    -machine virt,accel=hvf \
    -cpu cortex-a72 \
    -smp "${CPUS}" \
    -m "${MEMORY}" \
    -bios "${EFI_FIRMWARE}" \
    -drive if=virtio,file="${DISK_IMAGE}",format=qcow2 \
    -drive if=virtio,file="${ISO_PATH}",media=cdrom,readonly=on \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -device virtio-gpu-pci \
    -display default \
    -serial stdio \
    "$@"
QEMU_SCRIPT

# 替换变量
sed -i.bak \
    -e "s|__VM_DIR__|${VM_DIR}|g" \
    -e "s|__DISK_IMAGE__|${DISK_IMAGE}|g" \
    -e "s|__ISO_PATH__|${ISO_PATH}|g" \
    -e "s|__EFI_FIRMWARE__|${EFI_FIRMWARE}|g" \
    -e "s|__MEMORY__|${MEMORY}|g" \
    -e "s|__CPUS__|${CPUS}|g" \
    -e "s|__PUB_KEY__|${PUB_KEY}|g" \
    "$INSTALL_SCRIPT"
rm -f "${INSTALL_SCRIPT}.bak"
chmod +x "$INSTALL_SCRIPT"

info "QEMU安装脚本已生成: $INSTALL_SCRIPT"
echo ""
echo "============================================"
info "请运行以下命令启动安装:"
echo ""
echo "  ${INSTALL_SCRIPT}"
echo ""
echo "安装步骤:"
echo "  1. 在QEMU窗口中选择语言(简体中文)"
echo "  2. 选择'安装openKylin'"
echo "  3. 按提示分区(建议使用整个磁盘)"
echo "  4. 创建用户: 用户名=ljz, 密码=lima"
echo "  5. 等待安装完成"
echo "  6. 安装完成后，在系统内关机(sudo shutdown)"
echo "  7. 回到这里运行后安装配置"
echo ""
echo "安装完成后，运行:"
echo "  bash scripts/install-openkylin-vm.sh --post-install"
echo "============================================"