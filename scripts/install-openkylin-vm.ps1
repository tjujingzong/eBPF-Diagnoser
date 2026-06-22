# ============================================================
# openKylin QEMU 安装脚本 (Windows x86_64)
# 从ISO安装openKylin到qcow2磁盘镜像，使用QEMU运行
#
# 前提:
#   1. Windows 10/11 x86_64
#   2. 管理员权限的 PowerShell
#
# 使用方式:
#   .\scripts\install-openkylin-vm.ps1
#
# 安装完成后:
#   .\scripts\start-vm.ps1
#   ssh -p 2222 user@localhost
# ============================================================

param(
    [string]$IsoPath = "",
    [string]$VmDir = "$env:USERPROFILE\.openkylin-vm",
    [int]$MemoryMB = 8192,
    [int]$CpuCores = 4,
    [string]$DiskSize = "50G",
    [switch]$SkipQemuInstall,
    [switch]$SkipIsoDownload,
    [switch]$PostInstall
)

$ErrorActionPreference = "Stop"

# ============================================================
# 配置
# ============================================================
$VM_NAME = "openkylin"
$DISK_IMAGE = Join-Path $VmDir "$VM_NAME.qcow2"
$QEMU_SYSTEM = "qemu-system-x86_64"
$QEMU_IMG = "qemu-img"

# openKylin 2.0 SP2 x86_64 ISO 下载地址 (多个镜像源)
$ISO_URL = "https://mirrors.163.com/openkylin-cd/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso"
$ISO_MIRRORS = @(
    "https://mirrors.163.com/openkylin-cd/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso",
    "https://mirror.nju.edu.cn/openkylin-cdimage/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso",
    "https://mirrors.aliyun.com/openkylin-cdimage/2.0-SP2/openKylin-Desktop-V2.0-SP2-20260407-x86_64.iso"
)
$ISO_DEFAULT_PATH = Join-Path $env:USERPROFILE "Downloads\openKylin-Desktop-V2.0-SP2-x86_64.iso"

# ============================================================
# 辅助函数
# ============================================================
function Write-Info  { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }
function Write-Step  { param($msg) Write-Host "[STEP] $msg" -ForegroundColor Cyan }

# ============================================================
# 后安装阶段: 通过SSH配置VM内的eBPF环境
# ============================================================
if ($PostInstall) {
    Write-Step "通过后安装配置 openKylin VM..."
    Write-Info "请确保VM已启动且SSH服务已开启"
    Write-Info "将 postinstall-openkylin-win.sh 传入VM并执行..."

    $SSH_CMD = "ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=`$null"
    $SCP_CMD = "scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=`$null"

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Info "请在VM安装完成并启动SSH后，依次执行以下命令:"
    Write-Host ""
    Write-Host "  # 1. 测试SSH连接"
    Write-Host "  ssh -p 2222 user@localhost"
    Write-Host ""
    Write-Host "  # 2. 传输后安装脚本到VM"
    Write-Host "  scp -P 2222 scripts/postinstall-openkylin-win.sh user@localhost:/tmp/"
    Write-Host ""
    Write-Host "  # 3. 在VM内执行后安装脚本"
    Write-Host "  ssh -p 2222 user@localhost 'sudo bash /tmp/postinstall-openkylin-win.sh'"
    Write-Host ""
    Write-Host "  # 4. 传输项目代码到VM"
    Write-Host "  scp -rP 2222 . user@localhost:~/ebpf-diagnoser/"
    Write-Host ""
    Write-Host "  # 5. 在VM内运行诊断工具"
    Write-Host "  ssh -p 2222 user@localhost"
    Write-Host "  cd ~/ebpf-diagnoser"
    Write-Host "  sudo python3 -m src.main --probe all --duration 60"
    Write-Host "============================================" -ForegroundColor Cyan
    exit 0
}

# ============================================================
# 步骤1: 检查/安装 QEMU
# ============================================================
Write-Step "=========================================="
Write-Step "  openKylin VM 安装 (Windows QEMU)"
Write-Step "=========================================="

Write-Step "检查 QEMU 安装..."

$qemuFound = $false
# 检查 PATH 中是否有 qemu-system-x86_64
$existingQemu = Get-Command $QEMU_SYSTEM -ErrorAction SilentlyContinue
if ($existingQemu) {
    $qemuFound = $true
    Write-Info "QEMU 已安装: $($existingQemu.Source)"
}

# 常见 QEMU 安装路径
$qemuPaths = @(
    "C:\Program Files\qemu\$QEMU_SYSTEM.exe",
    "$env:LOCALAPPDATA\Programs\qemu\$QEMU_SYSTEM.exe",
    "C:\qemu\$QEMU_SYSTEM.exe"
)

if (-not $qemuFound) {
    foreach ($p in $qemuPaths) {
        if (Test-Path $p) {
            $qemuFound = $true
            Write-Info "QEMU 已安装在: $p"
            # 添加到当前会话 PATH
            $qemuDir = Split-Path $p -Parent
            $env:PATH = "$qemuDir;$env:PATH"
            break
        }
    }
}

if (-not $qemuFound -and -not $SkipQemuInstall) {
    Write-Info "QEMU 未安装，尝试通过 winget 安装..."
    try {
        winget install --id SoftwareFreedomConservancy.QEMU -e --accept-source-agreements --accept-package-agreements
        # 刷新 PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $existingQemu = Get-Command $QEMU_SYSTEM -ErrorAction SilentlyContinue
        if ($existingQemu) {
            $qemuFound = $true
            Write-Info "QEMU 安装成功: $($existingQemu.Source)"
        }
    } catch {
        Write-Warn "winget 安装 QEMU 失败: $_"
    }
}

if (-not $qemuFound) {
    Write-Err @"
QEMU 未安装。请手动安装:
  方法1: winget install SoftwareFreedomConservancy.QEMU
  方法2: 从 https://qemu.weilnetz.de/w64/ 下载安装包
  安装后重新运行此脚本。
"@
}

# 验证 qemu-img
$qemuImgCmd = Get-Command $QEMU_IMG -ErrorAction SilentlyContinue
if (-not $qemuImgCmd) {
    Write-Err "qemu-img 未找到，请确认 QEMU 安装完整且已加入 PATH"
}

# ============================================================
# 步骤2: 创建 VM 目录和磁盘
# ============================================================
Write-Step "创建 VM 目录..."
if (-not (Test-Path $VmDir)) {
    New-Item -ItemType Directory -Path $VmDir -Force | Out-Null
    Write-Info "目录已创建: $VmDir"
} else {
    Write-Info "目录已存在: $VmDir"
}

if (Test-Path $DISK_IMAGE) {
    Write-Warn "磁盘镜像已存在: $DISK_IMAGE"
    $answer = Read-Host "是否删除并重新创建? [y/N]"
    if ($answer -match '^[Yy]') {
        Remove-Item $DISK_IMAGE -Force
    } else {
        Write-Err "用户取消操作"
    }
}

Write-Step "创建 qcow2 磁盘镜像 ($DiskSize)..."
& $QEMU_IMG create -f qcow2 $DISK_IMAGE $DiskSize
Write-Info "磁盘镜像已创建: $DISK_IMAGE"

# ============================================================
# 步骤3: 获取/下载 ISO
# ============================================================
if (-not $IsoPath) {
    $IsoPath = $ISO_DEFAULT_PATH
}

if (-not (Test-Path $IsoPath) -and -not $SkipIsoDownload) {
    Write-Step "下载 openKylin ISO..."
    Write-Info "下载地址: $ISO_URL"
    Write-Info "保存路径: $IsoPath"
    Write-Info "文件大小约 7.8GB，请耐心等待..."

    $isoDir = Split-Path $IsoPath -Parent
    if (-not (Test-Path $isoDir)) {
        New-Item -ItemType Directory -Path $isoDir -Force | Out-Null
    }

    $downloaded = $false
    $ProgressPreference = 'SilentlyContinue'
    foreach ($mirror in $ISO_MIRRORS) {
        Write-Info "尝试镜像源: $mirror"
        try {
            Invoke-WebRequest -Uri $mirror -OutFile $IsoPath -UseBasicParsing -MaximumRedirection 10
            if (Test-Path $IsoPath) {
                Write-Info "ISO 下载完成"
                $downloaded = $true
                break
            }
        } catch {
            Write-Warn "镜像源失败: $($_.Exception.Message)"
            continue
        }
    }

    if (-not $downloaded) {
        Write-Warn "自动下载失败: $_"
        Write-Host ""
        Write-Host "请手动下载 ISO 文件:"
        Write-Host "  1. 浏览器打开: https://www.openkylin.top/downloads/"
        Write-Host "  2. 选择 openKylin 2.0 SP2 Desktop amd64 版本下载"
        Write-Host "  3. 重新运行脚本: .\install-openkylin-vm.ps1 -IsoPath 'C:\path\to\openkylin.iso'"
        exit 1
    }
}

if (-not (Test-Path $IsoPath)) {
    Write-Err @"
ISO 文件不存在: $IsoPath
请手动下载 openKylin Desktop amd64 ISO:
  下载地址: https://www.openkylin.top/downloads/
  然后运行: .\install-openkylin-vm.ps1 -IsoPath 'C:\path\to\openkylin.iso'
"@
}

$isoSize = (Get-Item $IsoPath).Length / 1MB
Write-Info "ISO 文件: $IsoPath ($([math]::Round($isoSize, 1)) MB)"

# ============================================================
# 步骤4: 查找 OVMF UEFI 固件
# ============================================================
Write-Step "查找 UEFI 固件 (OVMF)..."

$qemuCmd = (Get-Command $QEMU_SYSTEM).Source
$qemuDir = Split-Path $qemuCmd -Parent
$qemuShare = Join-Path $qemuDir "share"

$ovmfCode = Join-Path $qemuShare "edk2-x86_64-code.fd"
$ovmfVars = Join-Path $VmDir "openkylin-vars.fd"
$ovmfVarsSrc = Join-Path $qemuShare "edk2-i386-vars.fd"

$useUefi = $false
if ((Test-Path $ovmfCode) -and (Test-Path $ovmfVarsSrc)) {
    if (-not (Test-Path $ovmfVars)) {
        Copy-Item $ovmfVarsSrc $ovmfVars
    }
    $useUefi = $true
    Write-Info "UEFI 固件: OVMF pflash 模式"
} else {
    Write-Warn "未找到 OVMF UEFI 固件，将使用传统 BIOS 模式"
}

# ============================================================
# 步骤5: 生成 QEMU 启动脚本
# ============================================================
Write-Step "生成 QEMU 启动脚本..."

$startScript = @"
# openKylin VM 启动脚本 (由 install-openkylin-vm.ps1 生成)
# 生成时间: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

`$VmDir = "$VmDir"
`$DiskImage = "$DISK_IMAGE"
`$IsoPath = "$IsoPath"

`$QemuArgs = @(
    "-machine", "q35,accel=whpx",
    "-cpu", "qemu64,+kvm_pv_unhalt",
    "-smp", "$CpuCores",
    "-m", "${MemoryMB}M",
    $(if ($useUefi) { "`"-drive`", `"if=pflash,format=raw,readonly=on,file=$ovmfCode`",
    `"-drive`", `"if=pflash,format=raw,file=$ovmfVars`"," })
    "-drive", "if=virtio,file=`"$DISK_IMAGE`",format=qcow2",
    "-drive", "if=virtio,file=`"$IsoPath`",media=cdrom,readonly=on",
    "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
    "-device", "virtio-net-pci,netdev=net0",
    "-device", "virtio-gpu-pci",
    "-display", "sdl",
    "-serial", "stdio",
    "-name", "openKylin-VM"
)

Write-Host "启动 openKylin VM..."
Write-Host "  CPU: $CpuCores 核"
Write-Host "  内存: $([math]::Round($MemoryMB/1024, 1)) GB"
Write-Host "  磁盘: $DISK_IMAGE"
Write-Host "  ISO:  $IsoPath"
Write-Host "  SSH:  localhost:2222"
Write-Host ""

& $QEMU_SYSTEM `@QemuArgs
"@

$startScriptPath = Join-Path $VmDir "start-vm.ps1"
Set-Content -Path $startScriptPath -Value $startScript -Encoding UTF8
Write-Info "启动脚本已生成: $startScriptPath"

# ============================================================
# 步骤6: 显示安装指引
# ============================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Step "  安装 openKylin 操作指引"
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "请运行以下命令启动 VM 安装:" -ForegroundColor White
Write-Host ""
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$startScriptPath`"" -ForegroundColor Yellow
Write-Host ""
Write-Host "安装步骤:" -ForegroundColor White
Write-Host "  1. 在 QEMU 窗口中选择语言（简体中文）"
Write-Host "  2. 选择 '安装 openKylin'"
Write-Host "  3. 按提示完成分区（建议使用整个磁盘）"
Write-Host "  4. 创建用户（例如: user / password）"
Write-Host "  5. 等待安装完成（约10-20分钟）"
Write-Host "  6. 安装完成后重启或关机"
Write-Host "  7. 重启后确保 SSH 服务已启动"
Write-Host ""
Write-Host "安装完成后运行后安装配置:" -ForegroundColor White
Write-Host ""
Write-Host "  .\scripts\install-openkylin-vm.ps1 -PostInstall" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan

# ============================================================
# 步骤7: 询问是否立即启动
# ============================================================
$answer = Read-Host "是否立即启动 VM 开始安装? [Y/n]"
if ($answer -notmatch '^[Nn]') {
    Write-Info "启动 VM..."
    # 直接执行 QEMU
    $qemuArgs = @(
        "-machine", "q35,accel=whpx",
        "-cpu", "qemu64,+kvm_pv_unhalt",
        "-smp", "$CpuCores",
        "-m", "${MemoryMB}M"
    )
    if ($useUefi) {
        $qemuArgs += @(
            "-drive", "if=pflash,format=raw,readonly=on,file=$ovmfCode",
            "-drive", "if=pflash,format=raw,file=$ovmfVars"
        )
    }
    $qemuArgs += @(
        "-drive", "if=virtio,file=$DISK_IMAGE,format=qcow2",
        "-drive", "if=virtio,file=$IsoPath,media=cdrom,readonly=on",
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-device", "virtio-gpu-pci",
        "-display", "sdl",
        "-serial", "stdio",
        "-name", "openKylin-VM"
    )
    & $QEMU_SYSTEM @qemuArgs
} else {
    Write-Info "跳过启动，请稍后手动运行启动脚本"
}
