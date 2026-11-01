# CP-04 基准评测批量执行器（Windows PowerShell 5.1+ / PowerShell 7，零第三方依赖）。
#
# 作用：按目标清单逐条调用 `sitelens scan`，把每个目标的原始 JSON 落到
#       <out>/raw/<id>.json（stderr 落 <id>.log），并汇总 <out>/summary.csv；
#       同时写 run-meta.json 记录版本/配置哈希（可复现与反作弊要求）。
#
# 示例：
#   powershell -ExecutionPolicy Bypass -File benchmark/run.ps1 `
#       -Targets benchmark/targets/lab-matrix.sample.json `
#       -Mode standard `
#       -Truth benchmark/ground-truth/TEMPLATE.ground-truth.json   # 可选：跑完自动评分
#
# 参数：
#   -Targets <file>    目标清单（.json = {suite,version,targets:[{id,url}]}；.txt = 每行 "url" 或 "id url"）
#   -Out <dir>         输出目录（默认 benchmark/out/<suite>-<mode>-<时间戳>）
#   -Mode               fast | standard | deep（对应 profiles/<mode>.yml）
#   -Sitelens <path>    可执行文件（默认自动找 repo 根 sitelens.exe / bin / dist / PATH）
#   -Config <file>      自定义配置（覆盖 -Mode 的 profile；冻结口径时请固定写死）
#   -Truth <file>       若给出，跑完自动调用 score.mjs 评分（需要 node）
#   -TimeoutSec <n>     单目标硬超时（秒；超时杀进程并记 exit=124，默认 0=不限）
#   -Limit <n>          只跑前 n 个目标（冒烟用）
#   -Resume             跳过已有 raw/<id>.json 的目标（中断续跑）
#   -DryRun             只打印将执行的命令，不真正扫描
#
# 退出码：0 完成；2 参数/环境错误。

[CmdletBinding()]
param(
    [string]$Targets = "",
    [string]$Out = "",
    [ValidateSet("fast", "standard", "deep")]
    [string]$Mode = "standard",
    [string]$Sitelens = "",
    [string]$Config = "",
    [string]$Truth = "",
    [int]$TimeoutSec = 0,
    [int]$Limit = 0,
    [switch]$Resume,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$BenchDir = $PSScriptRoot
$RepoRoot = Split-Path -Parent $BenchDir

function Fail([string]$Message) {
    Write-Host "错误：$Message" -ForegroundColor Red
    exit 2
}

function Quote-Arg([string]$Value) {
    if ($Value -match '[\s"]') { return '"' + ($Value -replace '"', '\"') + '"' }
    return $Value
}

# ---------- 参数校验 ----------
if ([string]::IsNullOrWhiteSpace($Targets)) {
    Fail "缺少 -Targets <targets.json|targets.txt>（样例见 benchmark/targets/）"
}
$targetsPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Targets)
if (-not (Test-Path -LiteralPath $targetsPath)) { Fail "目标清单不存在：$targetsPath" }
$targetsPath = (Resolve-Path -LiteralPath $targetsPath).Path

if ($Config) {
    $configPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Config)
    if (-not (Test-Path -LiteralPath $configPath)) { Fail "配置不存在：$configPath" }
    $configPath = (Resolve-Path -LiteralPath $configPath).Path
}
else {
    $configPath = Join-Path $BenchDir "profiles/$Mode.yml"
    if (-not (Test-Path -LiteralPath $configPath)) { Fail "缺少 profile：$configPath" }
}

# ---------- 定位 sitelens ----------
function Resolve-SitelensExe([string]$Explicit) {
    if ($Explicit) {
        $p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Explicit)
        if (Test-Path -LiteralPath $p) { return (Resolve-Path -LiteralPath $p).Path }
        $cmd = Get-Command $Explicit -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        Fail "找不到 sitelens 可执行文件：$Explicit"
    }
    $candidates = @(
        (Join-Path $RepoRoot "sitelens.exe"),
        (Join-Path $RepoRoot "bin/sitelens.exe"),
        (Join-Path $RepoRoot "dist/sitelens.exe"),
        (Join-Path $RepoRoot "sitelens")
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
    }
    foreach ($name in @("sitelens.exe", "sitelens")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    Fail '未找到 sitelens：请先 go build -o sitelens.exe ./cmd/sitelens，或用 -Sitelens 指定'
}
$sitelensExe = Resolve-SitelensExe $Sitelens

# ---------- 目标清单解析 ----------
function Read-TargetList([string]$Path) {
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $list = New-Object System.Collections.ArrayList
    $suite = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $version = ""
    if ($ext -eq ".json") {
        try { $doc = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
        catch { Fail "目标清单 JSON 解析失败：$Path（$($_.Exception.Message)）" }
        if ($doc.suite) { $suite = [string]$doc.suite }
        if ($doc.version) { $version = [string]$doc.version }
        $items = @($doc.targets)
        if ($items.Count -eq 0) { Fail "目标清单没有 targets：$Path" }
        $i = 0
        foreach ($t in $items) {
            $i++
            $id = if ($t.id) { [string]$t.id } else { "t{0:d4}" -f $i }
            $url = [string]$t.url
            if ([string]::IsNullOrWhiteSpace($url)) { Fail "targets 第 $i 项缺少 url" }
            [void]$list.Add([pscustomobject]@{ Id = $id.Trim(); Url = $url.Trim() })
        }
    }
    else {
        $i = 0
        foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
            $line = $line.Trim()
            if ($line -eq "" -or $line.StartsWith("#")) { continue }
            $i++
            $parts = $line -split "\s+", 2
            if ($parts.Count -eq 1) {
                $id = "t{0:d4}" -f $i
                $url = $parts[0]
            }
            else {
                $id = $parts[0]
                $url = $parts[1]
            }
            [void]$list.Add([pscustomobject]@{ Id = $id.Trim(); Url = $url.Trim() })
        }
        if ($list.Count -eq 0) { Fail "目标清单为空：$Path" }
    }
    # id 去重（raw 文件名即 id，重复会互相覆盖）
    $seen = @{}
    foreach ($x in $list) {
        if ($seen.ContainsKey($x.Id)) { Fail "目标 id 重复：$($x.Id)" }
        $seen[$x.Id] = $true
    }
    return [pscustomobject]@{ Suite = $suite; Version = $version; List = @($list) }
}

$targetDoc = Read-TargetList $targetsPath
$allTargets = @($targetDoc.List)
if ($Limit -gt 0 -and $allTargets.Count -gt $Limit) { $allTargets = $allTargets[0..($Limit - 1)] }

# ---------- 输出目录与冻结元数据 ----------
if ($Out) {
    $runDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
}
else {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $runDir = Join-Path (Join-Path $BenchDir "out") ("{0}-{1}-{2}" -f $targetDoc.Suite, $Mode, $stamp)
}
$rawDir = Join-Path $runDir "raw"
New-Item -ItemType Directory -Force -Path $rawDir | Out-Null

if (-not $DryRun) {
    $exeVersion = ""
    try { $exeVersion = ((& $sitelensExe -version 2>$null | Out-String).Trim() -split "\r?\n")[0] } catch { }
    $meta = [ordered]@{
        product       = "SiteLens"
        suite         = $targetDoc.Suite
        suiteVersion  = $targetDoc.Version
        mode          = $Mode
        targets       = @($allTargets).Count
        targetsFile   = $targetsPath
        targetsSha256 = (Get-FileHash -LiteralPath $targetsPath -Algorithm SHA256).Hash.ToLowerInvariant()
        config        = $configPath
        configSha256  = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
        sitelens      = $sitelensExe
        sitelensVer   = $exeVersion
        timeoutSec    = $TimeoutSec
        limit         = $Limit
        host          = $env:COMPUTERNAME
        platform      = [System.Environment]::OSVersion.VersionString
        startedAt     = (Get-Date).ToString("o")
    }
    ($meta | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath (Join-Path $runDir "run-meta.json") -Encoding UTF8
}

Write-Host "SiteLens CP-04 benchmark"
Write-Host "  suite   : $($targetDoc.Suite) $($targetDoc.Version)"
Write-Host "  mode    : $Mode（config=$configPath）"
Write-Host "  sitelens: $sitelensExe"
Write-Host "  targets : $($allTargets.Count)"
Write-Host "  out     : $runDir"
Write-Host ""

# ---------- 逐目标执行 ----------
function Read-RawRow([string]$Id, [string]$Url, [string]$RawFile) {
    $row = [pscustomobject]@{
        target_id = $Id; url = $Url; exit_code = ""; duration_ms = ""
        verified = ""; vulnerabilities = ""; error = ""
    }
    if (-not (Test-Path -LiteralPath $RawFile)) { return $row }
    try {
        $j = Get-Content -LiteralPath $RawFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($j.url) { $row.url = [string]$j.url }
        $v = 0
        if ($null -ne $j.verified) { $v = @($j.verified).Count }
        $row.verified = $v
        $w = 0
        if ($null -ne $j.vulnerabilities) { $w = @($j.vulnerabilities).Count }
        $row.vulnerabilities = $w
        if ($j.error) { $row.error = [string]$j.error }
    }
    catch { $row.error = "raw JSON 解析失败" }
    return $row
}

$rows = New-Object System.Collections.ArrayList
$index = 0
$total = @($allTargets).Count
$failed = 0

foreach ($t in $allTargets) {
    $index++
    $rawFile = Join-Path $rawDir ($t.Id + ".json")
    $logFile = Join-Path $rawDir ($t.Id + ".log")

    if ($Resume -and (Test-Path -LiteralPath $rawFile)) {
        Write-Host ("[{0}/{1}] {2} 跳过（-Resume，已有 raw）" -f $index, $total, $t.Id)
        [void]$rows.Add((Read-RawRow $t.Id $t.Url $rawFile))
        continue
    }

    $argLine = (@("-config", (Quote-Arg $configPath), "scan", (Quote-Arg $t.Url)) -join " ")
    if ($DryRun) {
        Write-Host ('DRY-RUN: "{0}" {1} 1> "{2}" 2> "{3}"' -f $sitelensExe, $argLine, $rawFile, $logFile)
        continue
    }

    Write-Host ("[{0}/{1}] {2}  {3}" -f $index, $total, $t.Id, $t.Url)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $exitCode = 0
    $errMsg = ""
    try {
        $p = Start-Process -FilePath $sitelensExe -ArgumentList $argLine -WorkingDirectory $RepoRoot `
            -NoNewWindow -PassThru -RedirectStandardOutput $rawFile -RedirectStandardError $logFile
        if ($TimeoutSec -gt 0) {
            if (-not $p.WaitForExit($TimeoutSec * 1000)) {
                try { $p.Kill(); $p.WaitForExit(5000) } catch { }
                $exitCode = 124
                $errMsg = "timeout>${TimeoutSec}s"
            }
            else { $exitCode = $p.ExitCode }
        }
        else {
            $p.WaitForExit()
            $exitCode = $p.ExitCode
        }
    }
    catch {
        $exitCode = 127
        $errMsg = "启动失败：$($_.Exception.Message)"
    }
    $sw.Stop()
    if ($exitCode -ne 0 -and $errMsg -eq "") { $errMsg = "exit=$exitCode" }
    if ($exitCode -ne 0) { $failed++ }

    $row = Read-RawRow $t.Id $t.Url $rawFile
    $row.exit_code = $exitCode
    $row.duration_ms = $sw.ElapsedMilliseconds
    if ($errMsg -and -not $row.error) { $row.error = $errMsg }
    [void]$rows.Add($row)
    Write-Host ("    exit={0}  {1}ms  verified={2}  vulns={3}" -f $exitCode, $sw.ElapsedMilliseconds, $row.verified, $row.vulnerabilities)
}

# ---------- 汇总 ----------
$summaryPath = Join-Path $runDir "summary.csv"
if (-not $DryRun) {
    $rows | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "完成：$($rows.Count)/$total 个目标（失败 $failed）→ $runDir"
    Write-Host "  raw     : $rawDir"
    Write-Host "  summary : $summaryPath"
    if ($Truth) {
        $truthPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Truth)
        if (-not (Test-Path -LiteralPath $truthPath)) { Fail "truth 文件不存在：$truthPath" }
        $node = Get-Command node -ErrorAction SilentlyContinue
        if (-not $node) {
            Write-Host '提示：未找到 node，评分请手动运行 node benchmark/score.mjs --raw <raw> --truth <truth>' -ForegroundColor Yellow
        }
        else {
            Write-Host ""
            Write-Host "评分：node benchmark/score.mjs"
            & $node.Source (Join-Path $BenchDir "score.mjs") --raw $rawDir --truth $truthPath --out (Join-Path $runDir "score")
            if ($LASTEXITCODE -ne 0) { Write-Host "评分失败（exit=$LASTEXITCODE）" -ForegroundColor Red; exit 1 }
        }
    }
    else {
        Write-Host ""
        Write-Host "下一步评分（示例）："
        Write-Host ('  node benchmark/score.mjs --raw "{0}" --truth <ground-truth.json> --out "{1}"' -f $rawDir, (Join-Path $runDir 'score'))
    }
}

if ($failed -gt 0) { exit 1 }
exit 0
