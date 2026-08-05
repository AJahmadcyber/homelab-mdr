# Security-tooling watchdog heartbeat (endpoint side).
#
# Runs every 30s via the Wazuh agent (<localfile> full_command). Reports the
# state of the security processes this lab actually depends on, so the SIEM can
# reason about their absence.
#
# A SIEM fires on events that arrive - it cannot fire on one that never came.
# This converts absence into presence: while the endpoint is healthy it says so
# explicitly, and the moment it stops saying so, that silence is measurable.
#
# Scope is deliberately limited to tooling installed here. No coverage is
# claimed for products that are not present on this host.
$watch = 'MsMpEng','Sysmon64','wazuh-agent'
$seqFile = 'C:\secwatch\seq.txt'
$flag    = 'C:\secwatch\shutdown.flag'

# Monotonic sequence: lets the SIEM tell "nothing was sent" from "sent but lost".
$seq = 0
if (Test-Path $seqFile) { $seq = [int](Get-Content $seqFile -ErrorAction SilentlyContinue) }
$seq++
Set-Content $seqFile -Value $seq -Encoding ASCII

$up = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = [int]((Get-Date) - $up).TotalSeconds

# A shutdown marker older than this boot belongs to a previous cycle - clear it,
# or a stale marker would make a fresh kill look like a planned stop.
$shutdown = "no"
if (Test-Path $flag) {
    if ((Get-Item $flag).LastWriteTime -gt $up) { $shutdown = "pending" }
    else { Remove-Item $flag -Force -ErrorAction SilentlyContinue }
}

$state = foreach ($proc in $watch) {
    if (Get-Process -Name $proc -ErrorAction SilentlyContinue) { "$proc=UP" } else { "$proc=DOWN" }
}

"SECWATCH seq=$seq uptime=$uptime shutdown=$shutdown " + ($state -join " ")
