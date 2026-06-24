#!/bin/bash
# 构建自解压安装包
# Usage: bash scripts/build_installer.sh

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ARCH=$(uname -m)
STAGING=$(mktemp -d)
trap "rm -rf $STAGING" EXIT

# 从 pyproject.toml 提取版本号
VERSION=$(grep -m1 'version' "$PROJECT_DIR/pyproject.toml" | sed 's/.*"\(.*\)".*/\1/')
INSTALLER="$PROJECT_DIR/dist/ebpf-diagnoser-${VERSION}-${ARCH}.sh"

echo "=== 构建 ebpf-diagnoser 安装包 ==="
echo "版本: $VERSION"
echo "架构: $ARCH"

# 1. 编译BPF对象和C loader
echo "[1/4] 编译BPF程序和loader..."
make -C "$PROJECT_DIR" all

# 2. 创建staging目录布局
echo "[2/4] 收集文件..."
PKG="$STAGING/ebpf-diagnoser"
mkdir -p "$PKG"/{bin,bpf,src,config,rules}

# Python源码
cp -r "$PROJECT_DIR/src/"* "$PKG/src/"

# BPF预编译对象
cp "$PROJECT_DIR/build/bpf/"*.bpf.o "$PKG/bpf/"

# C loader二进制
cp "$PROJECT_DIR/build/bin/bpf_loader" "$PKG/bin/"

# 配置文件
cp -r "$PROJECT_DIR/config/"* "$PKG/config/"
cp -r "$PROJECT_DIR/rules/"* "$PKG/rules/"

# pyproject.toml
cp "$PROJECT_DIR/pyproject.toml" "$PKG/"

# 3. 创建tarball
echo "[3/4] 打包..."
tar -czf "$STAGING/payload.tar.gz" -C "$STAGING" ebpf-diagnoser

# 4. 拼接header + payload
echo "[4/4] 生成安装包..."
mkdir -p "$PROJECT_DIR/dist"
cat "$PROJECT_DIR/scripts/installer_header.sh" "$STAGING/payload.tar.gz" > "$INSTALLER"
chmod +x "$INSTALLER"

SIZE=$(du -h "$INSTALLER" | cut -f1)
echo ""
echo "=== 安装包构建完成 ==="
echo "文件: $INSTALLER"
echo "大小: $SIZE"
echo ""
echo "安装命令: sudo bash $INSTALLER"
