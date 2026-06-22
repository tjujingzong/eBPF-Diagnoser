# ============================================================
# openKylin VM 快速启动脚本 (Windows QEMU)
# 启动已安装好的 openKylin 虚拟机
#
# 使用方式:
#   .\scripts\start-vm.ps1
#
# 可选参数:
#   .\scripts\start-vm.ps1 -MemoryMB 16384 -CpuCores 8
#   .\scripts\start-vm.ps1 -NoGUI        # 无图形界面(仅SSH)
# ============================================================

param(
    [string]$VmDir = "$env:USERPROFILE\.openkylin-vm",
    [int]$MemoryMB = 8192,
    [int]$CpuCores = 4,
    [switch]$NoGUI,
    [switch]$InstallCD
)

$ErrorActionPreference = "Stop"

function Write-Info  { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Err   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ============================================================
# 配置
# ============================================================
$VM_NAME = "openkylin"
$DISK_IMAGE = Join-Path $VmDir "$VM_NAME.qcow2"
$QEMU_SYSTEM = "qemu-system-x86_64"

# ============================================================
# 前置检查
# ============================================================
if (-not (Test-Path $DISK_IMAGE)) {
    Write-Err "磁盘镜像不存在: $DISK_IMAGE`n请先运行 install-openkylin-vm.ps1 安装 openKylin VM"
}

$qemuCmd = Get-Command $QEMU_SYSTEM -ErrorAction SilentlyContinue
if (-not $qemuCmd) {
    # 尝试常见路径
    $paths = @("C:\Program Files\qemu\$QEMU_SYSTEM.exe", "$env:LOCALAPPDATA\Programs\qemu\$QEMU_SYSTEM.exe")
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $env:PATH = "$(Split-Path $p -Parent);$env:PATH"
            $qemuCmd = Get-Command $QEMU_SYSTEM -ErrorAction SilentlyContinue
            break
        }
    }
    if (-not $qemuCmd) {
        Write-Err "QEMU 未安装。请运行: winget install Software.QEMU"
    }
}

# 查找 OVMF 固件 (用于UEFI启动)
$qemuDir = Split-Path $qemuCmd.Source -Parent
$qemuShare = Join-Path $qemuDir "share"
$ovmfCode = Join-Path $qemuShare "edk2-x86_64-code.fd"
$ovmfVars = Join-Path $VmDir "openkylin-vars.fd"
$ovmfVarsSrc = Join-Path $qemuShare "edk2-i386-vars.fd"

$useUefi = $false
if ((Test-Path $ovmfCode) -and (Test-Path $ovmfVarsSrc)) {
    # 复制vars模板(每个VM需要独立的vars)
    if (-not (Test-Path $ovmfVars)) {
        Copy-Item $ovmfVarsSrc $ovmfVars
    }
    $useUefi = $true
}

# ============================================================
# 构建 QEMU 参数
# ============================================================
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
    "-drive", "if=virtio,file=$DISK_IMAGE,format=qcow2"
)

# 如果需要挂载安装ISO
if ($InstallCD) {
    $isoPath = Join-Path $env:USERPROFILE "Downloads\openKylin-Desktop-V2.0-SP2-x86_64.iso"
    if (Test-Path $isoPath) {
        $qemuArgs += @("-drive", "if=virtio,file=$isoPath,media=cdrom,readonly=on")
        Write-Info "已挂载安装ISO: $isoPath"
    } else {
        Write-Host "[WARN] ISO未找到: $isoPath" -ForegroundColor Yellow
    }
}

$qemuArgs += @(
    "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
    "-device", "virtio-net-pci,netdev=net0"
)

if ($NoGUI) {
    $qemuArgs += @("-nographic")
    Write-Info "无图形模式 (使用 Ctrl-A X 退出)"
} else {
    $qemuArgs += @("-device", "virtio-gpu-pci", "-display", "sdl")
}

$qemuArgs += @("-name", "openKylin-VM")

# ============================================================
# 启动
# ============================================================
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Info "启动 openKylin VM"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Info "CPU:    $CpuCores 核"
Write-Info "内存:   $([math]::Round($MemoryMB/1024, 1)) GB"
Write-Info "磁盘:   $DISK_IMAGE"
Write-Info "SSH:    ssh -p 2222 user@localhost"
Write-Info "UEFI:   $(if ($useUefi) { 'OVMF pflash' } else { '传统BIOS模式' })"
Write-Host ""

& $QEMU_SYSTEM @qemuArgs
