# openKylin eBPF 开发环境搭建指南 (VMware)

## 概述

本文档说明如何在 Windows 上通过 VMware 虚拟机安装 openKylin 操作系统，并配置 eBPF 开发环境，最终运行 eBPF Diagnoser 诊断工具。

## VM 信息

| 项目 | 值 |
|------|------|
| 用户名 | `ljz` |
| 密码 | `ky123456` |
| SSH 别名 | `kylin` |
| SSH 命令 | `ssh kylin` |
| VM IP | `192.168.93.130` |

## 环境要求

| 项目 | 要求 |
|------|------|
| 宿主机 | Windows 10/11 x86_64 |
| 虚拟机 | VMware Workstation / Player |
| CPU | 4 核以上（VM 分配 4 核） |
| 内存 | 4 GB 以上（VM 分配 4 GB） |
| 磁盘 | 50 GB 以上可用空间 |
| 网络 | VM 使用桥接或 NAT 模式，确保可从宿主机 SSH |

## 一、安装 VMware

从官网下载并安装 VMware Workstation 或 VMware Player：

- VMware Workstation Pro: https://www.vmware.com/products/workstation-pro
- VMware Workstation Player（免费）: https://www.vmware.com/products/workstation-player

## 二、下载 openKylin ISO

从镜像站下载 openKylin 2.0 SP2 Desktop x86_64 ISO（约 7.8 GB）：

| 镜像源 | 地址 |
|--------|------|
| 网易 | https://mirrors.163.com/openkylin-cd/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso |
| 南京大学 | https://mirror.nju.edu.cn/openkylin-cdimage/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso |
| 阿里云 | https://mirrors.aliyun.com/openkylin-cdimage/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso |

## 三、创建 VMware 虚拟机

1. **新建虚拟机** — 选择「自定义（高级）」
2. **安装来源** — 选择下载的 openKylin ISO 文件
3. **操作系统类型** — Linux → Ubuntu 64-bit（openKylin 基于 Ubuntu）
4. **磁盘大小** — 50 GB，存储为单个文件
5. **CPU** — 4 核
6. **内存** — 4096 MB (4 GB)
7. **网络** — NAT 或桥接模式（确保 VM 与宿主机互通）
8. **启动 VM** — 进入 openKylin 安装界面

## 四、安装 openKylin

1. **选择语言** — 选择「简体中文」
2. **安装 openKylin** — 点击「安装 openKylin」
3. **分区设置** — 选择「使用整个磁盘」（自动分区）
4. **创建用户** — 设置用户名和密码
5. **等待安装** — 约 10-20 分钟
6. **重启** — 安装完成后重启系统

## 五、配置 SSH 连接

### VM 内启用 SSH

在 openKylin 终端中安装并启动 SSH 服务：

```bash
sudo apt update && sudo apt install -y openssh-server
sudo systemctl enable ssh --now
```

### 宿主机配置 SSH 别名

编辑 `~/.ssh/config`，添加：

```
Host kylin
  HostName 192.168.93.130
  User ljz
```

> 将 IP 替换为你 VM 的实际 IP 地址（在 VM 中运行 `ip addr` 查看）。

### 测试连接

```powershell
ssh kylin
```

## 六、配置 VMware 共享文件夹（实时文件同步）

通过 VMware Shared Folders 将 Windows 上的项目目录直接映射到 VM，实现代码修改即时生效，无需手动同步。

### 1. VM 内安装 VMware Tools

```bash
sudo apt install -y open-vm-tools open-vm-tools-desktop
sudo systemctl enable open-vm-tools --now
```

验证安装：
```bash
vmware-toolbox-cmd -v   # 查看版本
```

### 2. VMware 图形界面配置

1. **VMware 菜单** → VM → Settings（设置）
2. 切到 **Options** 标签页
3. 选择 **Shared Folders**
4. 选 **Always enabled**（总是启用）
5. 点 **Add（添加）**：
   - Host Path: `E:\opensource2\eBPF-Diagnoser`
   - Name: `eBPF-Diagnoser`
6. 点 OK 保存

### 3. VM 内挂载共享目录

```bash
# 验证共享文件夹已识别
vmware-hgfsclient
# 应输出: eBPF-Diagnoser

# 创建挂载点并挂载
mkdir -p ~/ebpf-diagnoser
sudo vmhgfs-fuse .host:/eBPF-Diagnoser ~/ebpf-diagnoser -o allow_other

# 验证挂载成功
ls ~/ebpf-diagnoser/
# 应看到: config docker docs pyproject.toml README.md rules scripts src
```

### 4. 设置开机自动挂载（可选）

编辑 `/etc/fstab`，添加一行：

```bash
sudo sh -c 'echo ".host:/eBPF-Diagnoser /home/$(whoami)/ebpf-diagnoser fuse.vmhgfs-fuse allow_other,defaults 0 0" >> /etc/fstab'
```

> **注意**：如果 Windows 上 ISO 文件被挂载为虚拟光驱导致“正在被系统使用”错误，
> 可在 PowerShell 中执行：
> `Dismount-DiskImage -ImagePath "ISO文件路径"`

## 七、配置 eBPF 开发环境

### 使用脚本自动配置

```powershell
# 1. 传输安装脚本到 VM
scp scripts/postinstall-openkylin-win.sh kylin:/tmp/

# 2. 在 VM 内执行配置脚本
ssh kylin 'sudo bash /tmp/postinstall-openkylin-win.sh'
```

### 脚本自动完成的配置项

| 配置项 | 说明 |
|--------|------|
| SSH 服务 | 启用 root 登录和密钥认证 |
| 编译工具链 | build-essential, clang, llvm |
| eBPF 工具 | libbpf, bcc (源码编译), linux-headers |
| Python 环境 | Python 3, pip, venv, pyyaml, rich |
| 压测工具 | stress-ng, fio, sysbench |
| eBPF 验证 | 检查 BTF、BPF syscall、tracepoint |

### 手动配置（可选）

如果自动脚本部分包安装失败，可在 VM 内手动安装：

```bash
# 更新系统
sudo apt-get update && sudo apt-get upgrade -y

# eBPF 开发工具链 (基础包)
sudo apt-get install -y \
    build-essential clang llvm llvm-dev \
    libbpf-dev linux-headers-$(uname -r) \
    pkg-config

# BCC 需从源码编译 (openKylin 仓库中无 bpfcc-tools 包)
sudo apt-get install -y cmake flex bison libelf-dev libfl-dev \
    liblzma-dev libclang-dev libpolly-17-dev git
git clone --depth=1 https://github.com/iovisor/bcc.git /tmp/bcc
cd /tmp/bcc && mkdir build && cd build
cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr
make -j$(nproc) && sudo make install
echo /usr/lib64 | sudo tee /etc/ld.so.conf.d/bcc.conf
sudo ldconfig

# Python 环境
sudo apt-get install -y python3 python3-pip python3-venv
pip3 install pyyaml rich

# 压测工具
sudo apt-get install -y fio sysbench
# stress-ng 可能需要强制安装 (依赖冲突)
sudo apt-get install -y stress-ng 2>/dev/null || \
    (apt-get download stress-ng && sudo dpkg --force-depends -i stress-ng_*.deb)

# 验证 eBPF 支持
uname -r                          # 确认内核 >= 6.6
test -f /sys/kernel/btf/vmlinux   # BTF 支持
python3 -c "from bcc import BPF"  # BCC Python 绑定
```

## 八、部署并运行 eBPF Diagnoser

### 传输项目代码

```powershell
# 传输整个项目到 VM
scp -r . kylin:~/ebpf-diagnoser/
```

### 运行诊断工具

```powershell
# SSH 进入 VM
ssh kylin

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

## 九、常见问题

### SSH 连接失败

**排查步骤**：
1. 确认 VM 已启动且网络正常
2. 在 VM 内确认 SSH 服务：`sudo systemctl status ssh`
3. 确认 VM IP 地址：`ip addr`
4. 从宿主机 ping VM：`ping 192.168.93.130`

### VMware 网络不通

**NAT 模式**：VM 通过宿主机 NAT 上网，但宿主机不能直接访问 VM。建议改为**桥接模式**或配置端口转发。
**桥接模式**：VM 与宿主机在同一网段，可互相访问。

### BCC Python 绑定导入失败

**解决**：
```bash
# Ubuntu 可尝试系统包
sudo apt-get install -y python3-bpfcc 2>/dev/null

# openKylin 需从源码编译 BCC
sudo apt-get install -y cmake flex bison libelf-dev libfl-dev \
    liblzma-dev libclang-dev libpolly-17-dev git
git clone --depth=1 https://github.com/iovisor/bcc.git /tmp/bcc
cd /tmp/bcc && mkdir build && cd build
cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr
make -j$(nproc) && sudo make install
echo /usr/lib64 | sudo tee /etc/ld.so.conf.d/bcc.conf
sudo ldconfig
```

## 脚本文件说明

| 脚本 | 说明 | 运行位置 |
|------|------|----------|
| `scripts/postinstall-openkylin-win.sh` | VM 内 eBPF 环境配置 | openKylin VM 内 |
| `scripts/setup_env.sh` | 通用环境搭建 | Linux VM 内 |
| `scripts/sync-to-vm.ps1` | 项目文件同步到 VM | Windows PowerShell |
| `scripts/run_tests.sh` | 一键测试 5 类场景 | Linux VM 内 |
| `scripts/stress_*.sh` | 各类压测脚本 | Linux VM 内 |
| `scripts/benchmark_overhead.sh` | 性能开销基准测试 | Linux VM 内 |
