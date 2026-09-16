# Wails shell full-tree memory measurement (retry loop). ASCII only (PS5.1 GBK issue).
$ErrorActionPreference = "SilentlyContinue"
$exe = Join-Path $PSScriptRoot "..\desktop-wails\sitelens-wails.exe"

for ($attempt = 1; $attempt -le 4; $attempt++) {
  Write-Output "=== attempt $attempt ==="
  $p = Start-Process -FilePath $exe -ArgumentList "-hidden" -PassThru
  Start-Sleep 8
  if ($p.HasExited) { Write-Output "died-at-startup(code=$($p.ExitCode)) retry"; continue }
  Start-Sleep 30
  if ($p.HasExited) { Write-Output "died-at-settle(code=$($p.ExitCode)) retry"; continue }

  $shell = Get-Process sitelens-wails
  $engine = Get-Process sitelens
  if (-not $shell -or -not $engine) { Write-Output "procs-missing retry"; continue }

  $all = Get-CimInstance Win32_Process
  $wvBrowser = $all | Where-Object { $_.Name -eq "msedgewebview2.exe" -and $_.CommandLine -match "sitelens-wails" -and $_.CommandLine -notmatch "--type=" }
  $wvPids = @()
  if ($wvBrowser) {
    $ids = @{ [int]$wvBrowser.ProcessId = $true }
    $changed = $true
    while ($changed) {
      $changed = $false
      foreach ($proc in $all) {
        $ppid = [int]$proc.ParentProcessId; $cpid = [int]$proc.ProcessId
        if ($ids.ContainsKey($ppid) -and -not $ids.ContainsKey($cpid)) { $ids[$cpid] = $true; $changed = $true }
      }
    }
    $wvPids = $ids.Keys
  }

  $totalWS = 0.0; $totalPriv = 0.0; $count = 0
  foreach ($proc in @($shell) + @($engine)) {
    $totalWS += $proc.WorkingSet64/1MB; $totalPriv += $proc.PrivateMemorySize64/1MB; $count++
    "{0,-16} pid={1,-8} WS={2,8:N1} MB  Priv={3,8:N1} MB" -f $proc.Name, $proc.Id, ($proc.WorkingSet64/1MB), ($proc.PrivateMemorySize64/1MB)
  }
  foreach ($wvPid in $wvPids) {
    $gp = Get-Process -Id $wvPid
    if ($gp -and $gp.Name -eq "msedgewebview2") {
      $totalWS += $gp.WorkingSet64/1MB; $totalPriv += $gp.PrivateMemorySize64/1MB; $count++
      "{0,-16} pid={1,-8} WS={2,8:N1} MB  Priv={3,8:N1} MB" -f "msedgewebview2", $gp.Id, ($gp.WorkingSet64/1MB), ($gp.PrivateMemorySize64/1MB)
    }
  }
  "TOTAL_WS={0:N1} MB  TOTAL_PRIV={1:N1} MB  PROCS={2}" -f $totalWS, $totalPriv, $count
  break
}

Get-Process sitelens-wails,sitelens -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1
if (Get-Process sitelens-wails,sitelens -ErrorAction SilentlyContinue) { "LEFTOVER" } else { "CLEANED" }
