# Wails 壳全树内存测量：sitelens-wails + 引擎 sitelens + WebView2 子树
# 归属方法：从 msedgewebview2 浏览器主进程（命令行含 webview-exe-name/sitelens-wails
# 或 user-data-dir 含 sitelens-wails）沿 ParentProcessId 递归收集子进程。
$ErrorActionPreference = "SilentlyContinue"

$all = Get-CimInstance Win32_Process
function Get-Tree([int]$root) {
  $ids = @{ $root = $true }
  $changed = $true
  while ($changed) {
    $changed = $false
    foreach ($p in $all) {
      if (-not $ids.ContainsKey([int]$p.ParentProcessId) -and $ids.ContainsKey([int]$p.ProcessId) -eq $false -and $ids.ContainsKey([int]$p.ParentProcessId)) {
        $ids[[int]$p.ProcessId] = $true; $changed = $true
      }
    }
  }
  return $ids.Keys
}

# 1) 找壳与引擎
$shell = Get-Process sitelens-wails
$engine = Get-Process sitelens
if (-not $shell) { Write-Output "SHELL-NOT-RUNNING"; exit }

# 2) 找属于本壳的 webview2 浏览器主进程（命令行含 sitelens-wails）
$wvBrowser = $all | Where-Object { $_.Name -eq "msedgewebview2.exe" -and $_.CommandLine -match "sitelens-wails" -and $_.CommandLine -notmatch "--type=" }
$wvPids = @()
if ($wvBrowser) {
  $wvPids = Get-Tree ([int]$wvBrowser.ProcessId)
}

$totalWS = 0.0; $totalPriv = 0.0; $count = 0
foreach ($p in @($shell) + @($engine)) {
  $totalWS += $p.WorkingSet64/1MB; $totalPriv += $p.PrivateMemorySize64/1MB; $count++
  "{0,-16} pid={1,-8} WS={2,8:N1} MB  Priv={3,8:N1} MB" -f $p.Name, $p.Id, ($p.WorkingSet64/1MB), ($p.PrivateMemorySize64/1MB)
}
foreach ($pid2 in $wvPids) {
  $p = Get-Process -Id $pid2
  if ($p -and $p.Name -eq "msedgewebview2") {
    $totalWS += $p.WorkingSet64/1MB; $totalPriv += $p.PrivateMemorySize64/1MB; $count++
    "{0,-16} pid={1,-8} WS={2,8:N1} MB  Priv={3,8:N1} MB" -f "msedgewebview2", $p.Id, ($p.WorkingSet64/1MB), ($p.PrivateMemorySize64/1MB)
  }
}
"TOTAL_WS={0:N1} MB  TOTAL_PRIV={1:N1} MB  PROCS={2}" -f $totalWS, $totalPriv, $count
