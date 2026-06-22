# ============================================================
# SSH 连接 openKylin VM 脚本 (Windows)
# 连接到已启动的 openKylin QEMU VM
#
# 使用方式:
#   .\scripts\ssh-to-vm.ps1
#   .\scripts\ssh-to-vm.ps1 -Command "uname -r"
#   .\scripts\ssh-to-vm.ps1 -RunDiagnoser
#   .\scripts\ssh-to-vm.ps1 -DeployProject
# ============================================================

param(
    [int]$Port = 2222,
    [string]$User = "user",
    [string]$Command = "",
    [switch]$RunDiagnoser,
    [switch]$DeployProject,
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"

function Write-Info  { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Err   { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

$SSH_OPTS = "-p $Port -o StrictHostKeyChecking=no -o UserKnownHostsFile=`$null -o ConnectTimeout=10"
$SCP_OPTS = "-P $Port -o StrictHostKeyChecking=no -o UserKnownHostsFile=`$null"

# ============================================================
# 检查 SSH 连接
# ============================================================
Write-Info "检查 VM SSH 连接 (localhost:$Port)..."

$sshTest = Test-NetConnection -ComputerName localhost -Port $Port -WarningAction SilentlyContinue
if (-not $sshTest.TcpTestSucceeded) {
    Write-Err "无法连接到 localhost:$Port`n请确保 openKylin VM 已启动: .\scripts\start-vm.ps1"
}
Write-Info "SSH 连接正常"

# ============================================================
# 部署项目代码
# ============================================================
if ($DeployProject) {
    Write-Info "部署项目代码到 VM..."
    $projectDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    if (-not (Test-Path (Join-Path $projectDir "pyproject.toml"))) {
        $projectDir = $PSScriptRoot | Split-Path -Parent
    }
    Write-Info "项目目录: $projectDir"

    $scpCmd = "scp $SCP_OPTS -r `"$projectDir\*`" ${User}@localhost:~/ebpf-diagnoser/"
    Write-Info "执行: $scpCmd"
    Invoke-Expression $scpCmd
    Write-Info "项目代码已部署"
}

# ============================================================
# 运行诊断工具
# ============================================================
if ($RunDiagnoser) {
    Write-Info "在 VM 内运行 eBPF Diagnoser..."
    $sshCmd = "ssh $SSH_OPTS ${User}@localhost `"cd ~/ebpf-diagnoser && sudo python3 -m src.main --probe all --duration 60 --output json`""
    Write-Info "执行: $sshCmd"
    Invoke-Expression $sshCmd
}

# ============================================================
# 运行测试
# ============================================================
if ($RunTests) {
    Write-Info "在 VM 内运行一键测试..."
    $sshCmd = "ssh $SSH_OPTS ${User}@localhost `"cd ~/ebpf-diagnoser && sudo bash scripts/run_tests.sh`""
    Write-Info "执行: $sshCmd"
    Invoke-Expression $sshCmd
}

# ============================================================
# 执行自定义命令或直接 SSH 登录
# ============================================================
if ($Command) {
    Write-Info "执行远程命令: $Command"
    $sshCmd = "ssh $SSH_OPTS ${User}@localhost `"$Command`""
    Invoke-Expression $sshCmd
} elseif (-not $DeployProject -and -not $RunDiagnoser -and -not $RunTests) {
    Write-Info "SSH 登录 openKylin VM..."
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Info "连接信息:"
    Write-Host "  地址: localhost:$Port"
    Write-Host "  用户: $User"
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    ssh -p $Port -o StrictHostKeyChecking=no -o UserKnownHostsFile='$null' "${User}@localhost"
}
