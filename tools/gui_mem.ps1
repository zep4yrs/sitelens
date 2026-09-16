$procs = Get-Process electron,sitelens -ErrorAction SilentlyContinue
if (-not $procs) { Write-Output "NO-PROCESS"; exit }
$procs | ForEach-Object {
  "{0,-10} pid={1,-8} WS={2,8:N1} MB  Priv={3,8:N1} MB" -f $_.Name, $_.Id, ($_.WorkingSet64/1MB), ($_.PrivateMemorySize64/1MB)
}
$ws = ($procs | Measure-Object WorkingSet64 -Sum).Sum/1MB
$pr = ($procs | Measure-Object PrivateMemorySize64 -Sum).Sum/1MB
"TOTAL_WS={0:N1} MB  TOTAL_PRIV={1:N1} MB  PROCS={2}" -f $ws, $pr, $procs.Count
