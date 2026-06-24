# ============================================================
# 项目文件同步脚本 (Windows → openKylin VM)
# 实时监听文件变化并同步到 VM
#
# 使用方式:
#   .\scripts\sync-to-vm.ps1                  # 首次同步 + 持续监听
#   .\scripts\sync-to-vm.ps1 -Once             # 仅同步一次
#   .\scripts\sync-to-vm.ps1 -WatchInterval 2  # 自定义检测间隔(秒)
# ============================================================

param(
    [string]$Host_ = "kylin",
    [string]$RemoteDir = "~/ebpf-diagnoser",
    [switch]$Once,
    [int]$WatchInterval = 3
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent

function Write-Info  { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }

# 排除的文件/目录
$EXCLUDE = @(
    ".git", ".gitignore", "__pycache__", "*.pyc", "*.pyo",
    ".venv", "venv", "*.egg-info", ".DS_Store",
    "node_modules", "*.vmdk", "*.iso", "*.vmx"
)

function Sync-Files {
    Write-Info "正在同步文件到 VM ($Host_)..."
    
    # 构建 rsync 命令
    $excludeArgs = @()
    foreach ($pattern in $EXCLUDE) {
        $excludeArgs += "--exclude=$pattern"
    }
    
    # 使用 rsync over ssh
    $rsyncArgs = @(
        "-avz", "--delete",
        "--progress",
        "-e", "ssh"
    ) + $excludeArgs + @(
        "$ProjectRoot/",
        "${Host_}:$RemoteDir/"
    )
    
    & rsync @rsyncArgs 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Info "同步完成"
    } else {
        Write-Warn "rsync 不可用，回退到 scp..."
        # scp 回退方案
        & scp -r "$ProjectRoot\*" "${Host_}:$RemoteDir/" 2>&1
        Write-Info "scp 同步完成"
    }
}

# ============================================================
# 首次同步
# ============================================================
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Info "项目同步: $ProjectRoot → ${Host_}:$RemoteDir"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 确保 VM 上有目标目录
ssh $Host_ "mkdir -p $RemoteDir" 2>$null

Sync-Files

if ($Once) {
    Write-Info "单次同步完成，退出"
    exit 0
}

# ============================================================
# 持续监听文件变化
# ============================================================
Write-Host ""
Write-Info "开始监听文件变化 (每 ${WatchInterval} 秒检测一次)..."
Write-Info "按 Ctrl+C 停止同步"
Write-Host ""

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $ProjectRoot
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

$lastSync = Get-Date
$pendingChanges = $false

# 注册事件
$onChanged = Register-ObjectEvent $watcher Changed -Action {
    $global:pendingChanges = $true
}
$onCreated = Register-ObjectEvent $watcher Created -Action {
    $global:pendingChanges = $true
}
$onDeleted = Register-ObjectEvent $watcher Deleted -Action {
    $global:pendingChanges = $true
}
$onRenamed = Register-ObjectEvent $watcher Renamed -Action {
    $global:pendingChanges = $true
}

try {
    while ($true) {
        Start-Sleep -Seconds $WatchInterval
        
        if ($pendingChanges) {
            $elapsed = (Get-Date) - $lastSync
            if ($elapsed.TotalSeconds -ge $WatchInterval) {
                Write-Host ""
                Write-Info "检测到文件变化，正在同步..."
                Sync-Files
                $lastSync = Get-Date
                $pendingChanges = $false
            }
        }
    }
} finally {
    # 清理
    Unregister-Event -SourceIdentifier $onChanged.Name -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier $onCreated.Name -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier $onDeleted.Name -ErrorAction SilentlyContinue
    Unregister-Event -SourceIdentifier $onRenamed.Name -ErrorAction SilentlyContinue
    $watcher.Dispose()
    Write-Host ""
    Write-Info "同步已停止"
}
