# openKylin eBPF 开发环境搭建指南 (Windows QEMU)

## 概述

本文档说明如何在 Windows 上通过 QEMU 虚拟机安装 openKylin 操作系统，并配置 eBPF 开发环境，最终运行 eBPF Diagnoser 诊断工具。

## VM 信息

| 项目 | 值 |
|------|------|
| 用户名 | `user` |
| 密码 | `password` |
| SSH 端口 | `2222` (映射到 VM 的 22 端口) |
| SSH 命令 | `ssh -p 2222 user@localhost` |
| 磁盘镜像 | `%USERPROFILE%\.openkylin-vm\openkylin.qcow2` |

## 环境要求

| 项目 | 要求 |
|------|------|
| 宿主机 | Windows 10/11 x86_64 |
| CPU | 4 核以上，支持 Hyper-V (WHPX) |
| 内存 | 16 GB 以上（VM 分配 8 GB） |
| 磁盘 | 50 GB 以上可用空间 |
| 网络 | 可访问互联网（下载 ISO 和软件包） |

## 一、安装 QEMU

### 方法 1：通过 winget 安装（推荐）

```powershell
winget install SoftwareFreedomConservancy.QEMU --accept-package-agreements
```

安装后刷新 PATH 或重启终端：

```powershell
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
```

### 方法 2：手动下载安装

从 https://qemu.weilnetz.de/w64/ 下载最新版安装包并安装。

### 验证安装

```powershell
& "C:\Program Files\qemu\qemu-system-x86_64.exe" --version
```

预期输出类似：`QEMU emulator version 11.x.x`

## 二、下载 openKylin ISO

### 自动下载（使用脚本）

```powershell
.\scripts\install-openkylin-vm.ps1 -SkipQemuInstall
```

### 手动下载

从镜像站下载 openKylin 2.0 SP2 Desktop x86_64 ISO（约 7.8 GB）：

| 镜像源 | 地址 |
|--------|------|
| 网易 | https://mirrors.163.com/openkylin-cd/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso |
| 南京大学 | https://mirror.nju.edu.cn/openkylin-cdimage/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso |
| 阿里云 | https://mirrors.aliyun.com/openkylin-cdimage/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso |

下载后放到 `%USERPROFILE%\Downloads\` 目录。

## 三、创建虚拟机磁盘

```powershell
# 创建 VM 目录
New-Item -ItemType Directory -Path "$env:USERPROFILE\.openkylin-vm" -Force

# 创建 50GB qcow2 磁盘镜像
& "C:\Program Files\qemu\qemu-img.exe" create -f qcow2 "$env:USERPROFILE\.openkylin-vm\openkylin.qcow2" 50G
```

## 四、启动 VM 安装 openKylin

### 使用脚本启动（推荐）

```powershell
.\scripts\start-vm.ps1 -InstallCD
```

### 手动启动

```powershell
$vmDir = "$env:USERPROFILE\.openkylin-vm"
$isoPath = "$env:USERPROFILE\Downloads\openKylin-Desktop-V2.0-SP2-x86_64.iso"
$ovmfCode = "C:\Program Files\qemu\share\edk2-x86_64-code.fd"
$ovmfVars = "$vmDir\openkylin-vars.fd"

# 首次启动需要复制 OVMF vars 模板
if (-not (Test-Path $ovmfVars)) {
    Copy-Item "C:\Program Files\qemu\share\edk2-i386-vars.fd" $ovmfVars
}

& "C:\Program Files\qemu\qemu-system-x86_64.exe" `
    -machine q35,accel=whpx `
    -cpu qemu64,+kvm_pv_unhalt `
    -smp 4 -m 8192M `
    -drive "if=pflash,format=raw,readonly=on,file=$ovmfCode" `
    -drive "if=pflash,format=raw,file=$ovmfVars" `
    -drive "if=virtio,file=$vmDir\openkylin.qcow2,format=qcow2" `
    -drive "if=virtio,file=$isoPath,media=cdrom,readonly=on" `
    -netdev "user,id=net0,hostfwd=tcp::2222-:22" `
    -device virtio-net-pci,netdev=net0 `
    -vga std -display sdl `
    -name "openKylin-VM"
```

> **注意**：必须使用 `-vga std` 而非 `virtio-gpu-pci`，后者在 WHPX 模式下会导致黑屏。

### 安装步骤（在 QEMU 窗口中操作）

1. **UEFI 启动** — 等待 TianoCore logo 出现，进入 GRUB 菜单
2. **选择语言** — 选择「简体中文」
3. **安装 openKylin** — 点击「安装 openKylin」
4. **分区设置** — 选择「使用整个磁盘」（自动分区）
5. **创建用户** — 用户名: `user`，密码: `password`
6. **等待安装** — 约 10-20 分钟
7. **重启** — 安装完成后重启系统

### 安装后重启

重启时需要从磁盘启动（不再挂载 ISO），使用：

```powershell
.\scripts\start-vm.ps1
```

## 五、日常启动与 SSH 连接

### 启动 VM（安装完成后日常使用）

```powershell
# 方式 1：使用脚本
.\scripts\start-vm.ps1

# 方式 2：完整命令
& "C:\Program Files\qemu\qemu-system-x86_64.exe" `
    -machine q35,accel=whpx `
    -cpu qemu64,+kvm_pv_unhalt `
    -smp 4 -m 8192M `
    -drive "if=pflash,format=raw,readonly=on,file=C:\Program Files\qemu\share\edk2-x86_64-code.fd" `
    -drive "if=pflash,format=raw,file=$env:USERPROFILE\.openkylin-vm\openkylin-vars.fd" `
    -drive "if=virtio,file=$env:USERPROFILE\.openkylin-vm\openkylin.qcow2,format=qcow2" `
    -netdev "user,id=net0,hostfwd=tcp::2222-:22" `
    -device virtio-net-pci,netdev=net0 `
    -vga std -display sdl `
    -name "openKylin-VM"
```

### SSH 连接

VM 启动后，从 Windows 连接（用户名 `user`，密码 `password`）：

```powershell
# SSH 连接
ssh -p 2222 user@localhost

# SCP 传文件
scp -P 2222 文件名 user@localhost:~/

# 使用项目脚本连接
.\scripts\ssh-to-vm.ps1
```

> 端口映射：QEMU 将 VM 的 22 端口映射到宿主机的 2222 端口。

## 六、配置 eBPF 开发环境

### 使用脚本自动配置

```powershell
# 1. 传输后安装脚本到 VM
scp -P 2222 scripts/postinstall-openkylin-win.sh user@localhost:/tmp/

# 2. 在 VM 内执行配置脚本
ssh -p 2222 user@localhost 'sudo bash /tmp/postinstall-openkylin-win.sh'
```

### 脚本自动完成的配置项

| 配置项 | 说明 |
|--------|------|
| SSH 服务 | 启用 root 登录和密钥认证 |
| 编译工具链 | build-essential, clang, llvm |
| eBPF 工具 | libbpf, bcc, bpftool, linux-headers |
| Python 环境 | Python 3, pip, venv, pyyaml, rich |
| 压测工具 | stress-ng, fio, sysbench |
| eBPF 验证 | 检查 BTF、BPF syscall、tracepoint |

### 手动配置（可选）

如果自动脚本部分包安装失败，可在 VM 内手动安装：

```bash
# 更新系统
sudo apt-get update && sudo apt-get upgrade -y

# eBPF 开发工具链
sudo apt-get install -y \
    build-essential clang llvm llvm-dev \
    libbpf-dev linux-headers-$(uname -r) \
    bpfcc-tools python3-bpfcc libbpfcc-dev \
    bpftool pkg-config

# Python 环境
sudo apt-get install -y python3 python3-pip python3-venv
pip3 install pyyaml rich

# 压测工具
sudo apt-get install -y stress-ng fio sysbench

# 验证 eBPF 支持
uname -r                          # 确认内核 >= 6.6
test -f /sys/kernel/btf/vmlinux   # BTF 支持
bpftool feature | grep bpf        # BPF syscall
python3 -c "from bcc import BPF"  # BCC Python 绑定
```

## 七、部署并运行 eBPF Diagnoser

### 传输项目代码

```powershell
# 方式 1：使用脚本
.\scripts\ssh-to-vm.ps1 -DeployProject

# 方式 2：手动 scp
scp -rP 2222 . user@localhost:~/ebpf-diagnoser/
```

### 运行诊断工具

```powershell
# 方式 1：使用脚本运行全部探针
.\scripts\ssh-to-vm.ps1 -RunDiagnoser

# 方式 2：SSH 进入 VM 手动操作
ssh -p 2222 user@localhost

cd ~/ebpf-diagnoser
source ~/ebpf-venv/bin/activate

# 启动所有探针
sudo python3 -m src.main --probe all --duration 60

# 指定探针 + JSON 输出
sudo python3 -m src.main --probe cpu,io --duration 60 --output json
```

### 运行压测验证

```bash
# 在 VM 内运行

# CPU 压测 + 诊断
sudo bash scripts/stress_cpu.sh &
sudo python3 -m src.main --probe cpu --duration 60

# 全场景组合压测
sudo bash scripts/stress_composite.sh &
sudo python3 -m src.main --probe all --duration 120 --output all

# 一键测试 (5 类场景自动验证)
sudo bash scripts/run_tests.sh

# 性能开销基准测试
sudo bash scripts/benchmark_overhead.sh
```

## 八、常见问题

### QEMU 黑屏

**原因**：使用了 `virtio-gpu-pci` 显示设备。
**解决**：改用 `-vga std` 替代 `-device virtio-gpu-pci`。

### OVMF 固件加载失败

**原因**：使用了 `-bios` 参数加载 OVMF。
**解决**：使用 `-drive if=pflash` 方式加载 OVMF code 和 vars 文件。

### WHPX 加速不可用

**原因**：Hyper-V 未启用。
**解决**：
```powershell
# 以管理员权限运行
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
# 重启电脑
```

### SSH 连接失败

**排查步骤**：
1. 确认 VM 已启动且 QEMU 进程运行中
2. 在 VM 内确认 SSH 服务：`sudo systemctl status ssh`
3. 确认端口 2222 未被占用：`netstat -an | findstr 2222`

### BCC Python 绑定导入失败

**解决**：
```bash
# 尝试安装系统包
sudo apt-get install -y python3-bpfcc

# 或从源码编译 BCC
git clone --depth=1 https://github.com/iovisor/bcc.git /tmp/bcc
cd /tmp/bcc && mkdir build && cd build
cmake .. -DPYTHON_CMD=python3
make -j$(nproc) && sudo make install
```

## 脚本文件说明

| 脚本 | 说明 | 运行位置 |
|------|------|----------|
| `scripts/install-openkylin-vm.ps1` | QEMU 安装 + ISO 下载 + VM 创建 | Windows PowerShell |
| `scripts/start-vm.ps1` | 快速启动 openKylin VM | Windows PowerShell |
| `scripts/ssh-to-vm.ps1` | SSH 连接/部署/运行工具 | Windows PowerShell |
| `scripts/postinstall-openkylin-win.sh` | VM 内 eBPF 环境配置 | openKylin VM 内 |
| `scripts/setup_env.sh` | 通用环境搭建 | Linux VM 内 |
| `scripts/run_tests.sh` | 一键测试 5 类场景 | Linux VM 内 |
| `scripts/stress_*.sh` | 各类压测脚本 | Linux VM 内 |
| `scripts/benchmark_overhead.sh` | 性能开销基准测试 | Linux VM 内 |
