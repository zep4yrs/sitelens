<#
.SYNOPSIS
  SiteLens 发布物校验（零依赖）：版本一致性 / 产物命名 / PE 头 / 签名占位 / 更新清单 / 文档占位。

.DESCRIPTION
  规则与权威来源见同目录 release-matrix.md（R1~R12）。不构建、不修改任何文件，只读取与报告。
  兼容 Windows PowerShell 5.1 与 PowerShell 7（不依赖 Node/Go/签名工具）。

.PARAMETER DryRun
  只报告不失败（缺产物/占位也返回 0），用于构建前的规划检查。

.PARAMETER ExpectedVersion
  期望版本号（如 5.2.0）；与壳/引擎版本不一致时 FAIL。

.PARAMETER RequireSigned
  要求安装包已签名；未签名/无法验证时 FAIL（DryRun 下仍只报告）。

.PARAMETER Strict
  严格模式：暂存目录不完整、latest.yml 缺失/占位、发行说明占位未回填也视为 FAIL。

.EXAMPLE
  pwsh scripts/release/check.ps1 -DryRun
  pwsh scripts/release/check.ps1 -ExpectedVersion 5.2.0
  pwsh scripts/release/check.ps1 -RequireSigned -Strict
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$ExpectedVersion = "",
    [switch]$RequireSigned,
    [switch]$Strict
)

$ErrorActionPreference = "Stop"

# ---------- 结果收集 ----------
$script:Results = New-Object System.Collections.ArrayList
function Add-Result {
    param(
        [string]$Id,
        [ValidateSet("PASS", "WARN", "FAIL", "SKIP")] [string]$Level,
        [string]$Message,
        [string]$Detail = ""
    )
    [void]$script:Results.Add([PSCustomObject]@{
        Id      = $Id
        Level   = $Level
        Message = $Message
        Detail  = $Detail
    })
}

function Get-Text {
    param([string]$Path)
    try { return [System.IO.File]::ReadAllText($Path) } catch { return $null }
}

function Get-ConstVersion {
    param([string]$Path, [string]$Pattern)
    $text = Get-Text $Path
    if ($null -eq $text) { return $null }
    $m = [regex]::Match($text, $Pattern)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Read-PeMagic {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $b0 = $fs.ReadByte()
            $b1 = $fs.ReadByte()
        } finally { $fs.Dispose() }
        if ($b0 -eq 0x4D -and $b1 -eq 0x5A) { return "MZ" }   # 'MZ'
        return ("{0:X2}{1:X2}" -f $b0, $b1)
    } catch { return "ERR" }
}

function Test-ManifestKey {
    param([string]$Text, [string]$Key)
    $m = [regex]::Match($Text, "(?m)^\s*" + [regex]::Escape($Key) + "\s*:\s*(.+?)\s*$")
    if (-not $m.Success) { return $null }
    return $m.Groups[1].Value.Trim().Trim("'").Trim('"')
}

# ---------- 定位仓库根 ----------
$root = $null
if ($PSScriptRoot) {
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
    if (Test-Path -LiteralPath (Join-Path $candidate "go.mod")) { $root = $candidate }
}
if (-not $root) {
    Write-Host "× 无法定位仓库根（需从 scripts/release/ 下运行，且仓库含 go.mod）" -ForegroundColor Red
    exit 2
}

Write-Host "== SiteLens 发布物校验（$(if ($DryRun) { 'DryRun' } else { 'Release' })）==" -ForegroundColor Cyan
Write-Host "   root: $root"
Write-Host ""

# ---------- R1/R2/R3 版本一致性 ----------
$verShell = Get-ConstVersion (Join-Path $root "desktop-wails/version.go") 'const\s+Version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"'
$verEngine = Get-ConstVersion (Join-Path $root "internal/server/server.go") 'const\s+Version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"'

if ($null -eq $verShell) {
    Add-Result "R1" "FAIL" "desktop-wails/version.go 未能解析 const Version"
} else {
    Add-Result "R1" "PASS" "壳版本 $verShell"
}
if ($null -eq $verEngine) {
    Add-Result "R2" "FAIL" "internal/server/server.go 未能解析 const Version"
} else {
    Add-Result "R2" "PASS" "引擎版本 $verEngine"
}
if ($verShell -and $verEngine -and $verShell -ne $verEngine) {
    Add-Result "R2" "FAIL" "壳/引擎版本不一致" ("壳=$verShell 引擎=$verEngine")
}
$ver = if ($verShell) { $verShell } else { $verEngine }

if ($ExpectedVersion -ne "") {
    if ($ver -eq $ExpectedVersion) {
        Add-Result "R3" "PASS" "与期望版本一致（$ExpectedVersion）"
    } else {
        Add-Result "R3" "FAIL" "与期望版本不一致" ("期望=$ExpectedVersion 实际=$ver")
    }
} else {
    Add-Result "R3" "SKIP" "未传 -ExpectedVersion"
}

# ---------- R4/R5/R6/R7 产物 ----------
$releaseDir = Join-Path $root "dist/release"
$stagingDir = Join-Path $root "dist/wails/SiteLens"
$setupName = if ($ver) { "SiteLens-Setup-$ver.exe" } else { $null }
$setupPath = if ($setupName) { Join-Path $releaseDir $setupName } else { $null }

if ($ver -and (Test-Path -LiteralPath $releaseDir)) {
    $exes = @(Get-ChildItem -LiteralPath $releaseDir -Filter "SiteLens-Setup-*.exe" -File -ErrorAction SilentlyContinue)
    if ($exes.Count -eq 0) {
        Add-Result "R4" ($(if ($DryRun) { "WARN" } else { "FAIL" })) "dist/release 下无安装包"
    } else {
        $bad = @($exes | Where-Object { $_.Name -notmatch '^SiteLens-Setup-(\d+\.\d+\.\d+[^\\/]*)\.exe$' -or $_.Name -ne $setupName })
        if ($bad.Count -gt 0) {
            Add-Result "R4" "FAIL" "安装包命名/版本不符合规范" (($bad | ForEach-Object { $_.Name }) -join ", ")
        } else {
            Add-Result "R4" "PASS" "安装包命名规范：$setupName"
        }
    }
    if ($setupPath -and (Test-Path -LiteralPath $setupPath)) {
        $magic = Read-PeMagic $setupPath
        $size = (Get-Item -LiteralPath $setupPath).Length
        if ($magic -eq "MZ" -and $size -gt 1MB) {
            Add-Result "R4" "PASS" "安装包 PE 头正确（MZ，$size bytes）"
        } else {
            Add-Result "R4" "FAIL" "安装包疑似非 Windows PE 或体积异常" ("magic=$magic size=$size")
        }
    }
} else {
    Add-Result "R4" ($(if ($DryRun) { "WARN" } else { "FAIL" })) "dist/release 不存在或版本未知（未出包？）"
}

if (Test-Path -LiteralPath $stagingDir) {
    $need = @("sitelens.exe", "engine/sitelens-engine.exe")
    $missing = @()
    foreach ($n in $need) {
        $p = Join-Path $stagingDir $n
        if (-not (Test-Path -LiteralPath $p)) { $missing += $n; continue }
        $magic = Read-PeMagic $p
        if ($magic -ne "MZ") { Add-Result "R5" "FAIL" "暂存产物非 PE：$n" "magic=$magic" }
    }
    if ($missing.Count -gt 0) {
        Add-Result "R6" ($(if ($DryRun) { "WARN" } else { "FAIL" })) "暂存目录不完整" (($missing -join ", "))
    } else {
        Add-Result "R5" "PASS" "暂存壳/引擎均为 Windows PE"
    }
    $dataDir = Join-Path $stagingDir "engine/data"
    if (-not (Test-Path -LiteralPath $dataDir)) {
        Add-Result "R6" ($(if ($DryRun) { "WARN" } else { "FAIL" })) "缺少 engine/data 只读资产目录"
    } else {
        $cnt = @(Get-ChildItem -LiteralPath $dataDir -Recurse -File -ErrorAction SilentlyContinue).Count
        Add-Result "R6" "PASS" "engine/data 就位（$cnt 个文件）"
    }
} else {
    Add-Result "R6" ($(if ($DryRun) { "WARN" } else { "FAIL" })) "暂存目录不存在（先跑 tools/wails_build.sh）"
}

# ---------- R7 latest.yml（更新清单，存在才校验） ----------
$latestPath = Join-Path $releaseDir "latest.yml"
$latestText = if (Test-Path -LiteralPath $latestPath) { Get-Text $latestPath } else { $null }
if ($null -ne $latestText) {
    $lv = Test-ManifestKey $latestText "version"
    $lp = Test-ManifestKey $latestText "path"
    $ls = Test-ManifestKey $latestText "sha512"
    $bad = @()
    if ($ver -and $lv -ne $ver) { $bad += "version=$lv（期望 $ver）" }
    if ($setupName -and $lp -ne $setupName) { $bad += "path=$lp（期望 $setupName）" }
    if (-not $ls -or $ls -match '^(__|TODO|\$|待)') { $bad += "sha512 缺失或占位" }
    if ($bad.Count -gt 0) {
        Add-Result "R7" ($(if ($Strict) { "FAIL" } else { "WARN" })) "latest.yml 字段不自洽" (($bad -join "；"))
    } else {
        Add-Result "R7" "PASS" "latest.yml 字段自洽"
    }
} else {
    Add-Result "R7" ($(if ($Strict) { "FAIL" } else { "WARN" })) "latest.yml 缺失（GitHub desktop-stable 三件套需另生成）"
}

# ---------- R8 签名状态（Authenticode 占位） ----------
$win = ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)
$sigTarget = $null
if ($setupPath -and (Test-Path -LiteralPath $setupPath)) { $sigTarget = $setupPath }
elseif (Test-Path -LiteralPath (Join-Path $stagingDir "sitelens.exe")) { $sigTarget = Join-Path $stagingDir "sitelens.exe" }

if ($null -eq $sigTarget) {
    Add-Result "R8" ($(if ($RequireSigned) { "FAIL" } else { "SKIP" })) "无可校验签名的产物"
} elseif (-not $win) {
    Add-Result "R8" ($(if ($RequireSigned) { "FAIL" } else { "SKIP" })) "非 Windows 环境，跳过 Authenticode 校验"
} else {
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $sigTarget -ErrorAction Stop } catch { $sig = $null }
    if ($null -eq $sig) {
        Add-Result "R8" ($(if ($RequireSigned) { "FAIL" } else { "WARN" })) "无法读取签名状态"
    } elseif ($sig.Status -eq "Valid") {
        Add-Result "R8" "PASS" "已签名（$($sig.SignerCertificate.Subject)）"
    } else {
        $msg = "未签名/签名无效（$($sig.Status)）——Authenticode 为占位项（release-matrix.md §2/R8）"
        Add-Result "R8" ($(if ($RequireSigned) { "FAIL" } else { "WARN" })) $msg
    }
}

# ---------- R9/R10 文档 ----------
$relBody = $null
if ($ver) {
    $cand1 = Join-Path $root ("docs/release-" + $ver + "/release-body-" + $ver + ".md")
    $cand2 = Join-Path $root ("docs/release-" + $ver + "/release-body.md")
    if (Test-Path -LiteralPath $cand1) { $relBody = $cand1 }
    elseif (Test-Path -LiteralPath $cand2) { $relBody = $cand2 }
}
if ($relBody) {
    $body = Get-Text $relBody
    $ph = ([regex]::Matches($body, "【待发布[^】]*】")).Count
    if ($ph -gt 0) {
        Add-Result "R9" ($(if ($Strict) { "FAIL" } else { "WARN" })) "发行说明存在 $ph 处【待发布】占位未回填" $relBody
    } else {
        Add-Result "R9" "PASS" "发行说明无未回填占位"
    }
} else {
    Add-Result "R9" ($(if ($Strict) { "FAIL" } else { "WARN" })) "未找到当前版本的发行说明（docs/release-<ver>/release-body-<ver>.md）"
}

$chg = Get-Text (Join-Path $root "CHANGELOG.md")
if ($null -ne $chg -and $ver) {
    if ($chg -match ("(?m)^##\s+v" + [regex]::Escape($ver) + "(\s|（|\(|$)")) {
        Add-Result "R10" "PASS" "CHANGELOG 含 v$ver 段"
    } else {
        Add-Result "R10" ($(if ($Strict) { "FAIL" } else { "WARN" })) "CHANGELOG 缺少 v$ver 段"
    }
} else {
    Add-Result "R10" ($(if ($Strict) { "FAIL" } else { "WARN" })) "未找到 CHANGELOG.md 或版本未知"
}

# ---------- R11/R12 npm CLI 与 5 平台引擎包 ----------
$pkgPath = Join-Path $root "tui/package.json"
if (Test-Path -LiteralPath $pkgPath) {
    try {
        $pkg = Get-Content -LiteralPath $pkgPath -Raw | ConvertFrom-Json
        if ($pkg.name -ne "@fengqiao666/sitelens-cli") {
            Add-Result "R11" "WARN" "CLI 包名与发布约定不一致" ("实际=" + $pkg.name)
        } else {
            $binRel = $null
            if ($pkg.bin -and $pkg.bin.sitelens) { $binRel = $pkg.bin.sitelens }
            if ($binRel -and (Test-Path -LiteralPath (Join-Path $root ("tui/" + $binRel)))) {
                Add-Result "R11" "PASS" "CLI 包名/入口正常（v$($pkg.version)）"
            } else {
                Add-Result "R11" "WARN" "CLI bin 入口不存在" ("bin=" + $binRel)
            }
        }
    } catch {
        Add-Result "R11" "WARN" "tui/package.json 解析失败" $_.Exception.Message
    }
} else {
    Add-Result "R11" "SKIP" "无 tui/package.json"
}

$enginesRoot = Join-Path $root "tui/packages"
if (Test-Path -LiteralPath $enginesRoot) {
    $map = @{
        "sitelens-win32-x64-engine"     = "win64";
        "sitelens-linux-x64-engine"     = "linux64";
        "sitelens-linux-arm64-engine"   = "linux-arm64";
        "sitelens-darwin-x64-engine"    = "mac64";
        "sitelens-darwin-arm64-engine"  = "mac-arm64"
    }
    $badE = @()
    $found = 0
    foreach ($dir in Get-ChildItem -LiteralPath $enginesRoot -Directory -ErrorAction SilentlyContinue) {
        if (-not $map.ContainsKey($dir.Name)) { continue }
        $found++
        $token = $map[$dir.Name]
        $files = @(Get-ChildItem -LiteralPath $dir.FullName -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match ("^SiteLens_" + [regex]::Escape($token) + "_engine_.+?\.exe$") })
        if ($files.Count -eq 0) { $badE += ($dir.Name + "（缺 SiteLens_" + $token + "_engine_*）") }
    }
    if ($found -eq 0) {
        Add-Result "R12" "SKIP" "tui/packages 存在但无已知平台包目录"
    } elseif ($badE.Count -gt 0) {
        Add-Result "R12" "WARN" "引擎平台包产物命名不符" (($badE -join "；"))
    } else {
        Add-Result "R12" "PASS" "引擎平台包命名正常（$found 个平台）"
    }
} else {
    Add-Result "R12" "SKIP" "无 tui/packages（未构建 CLI 引擎包）"
}

# ---------- 汇总 ----------
$pass = @($script:Results | Where-Object { $_.Level -eq "PASS" }).Count
$warn = @($script:Results | Where-Object { $_.Level -eq "WARN" }).Count
$fail = @($script:Results | Where-Object { $_.Level -eq "FAIL" }).Count
$skip = @($script:Results | Where-Object { $_.Level -eq "SKIP" }).Count

foreach ($r in $script:Results) {
    $color = switch ($r.Level) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "DarkGray" }
    }
    $line = "  [{0}] {1,-3} {2}" -f $r.Level, $r.Id, $r.Message
    Write-Host $line -ForegroundColor $color
    if ($r.Detail) { Write-Host ("        " + $r.Detail) -ForegroundColor DarkGray }
}
Write-Host ""
Write-Host ("== 结果：PASS={0} WARN={1} FAIL={2} SKIP={3} ==" -f $pass, $warn, $fail, $skip)
if ($DryRun) {
    Write-Host "== DryRun：只报告不失败（退出码 0）==" -ForegroundColor Cyan
    exit 0
}
if ($fail -gt 0) {
    Write-Host "== 发布校验失败：请按上一节 FAIL 项修复后重试 ==" -ForegroundColor Red
    exit 1
}
Write-Host "== 发布校验通过 ==" -ForegroundColor Green
exit 0
