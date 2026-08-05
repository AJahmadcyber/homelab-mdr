# Graceful-shutdown announcement (endpoint side).
#
# Triggered by a Scheduled Task on System event 1074 (shutdown initiated), which
# fires before services stop - the agent and networking are still alive.
#
# Writes with an explicit ReadWrite share: the Wazuh agent holds this file open
# while tailing it, so Add-Content fails with a sharing violation. That failure
# would only surface during a real shutdown, when it is too late to notice.
#
# The file is tailed (log_format syslog), not polled, so the line ships within
# seconds rather than waiting for the next 30s heartbeat - a shutdown can
# complete in less time than one heartbeat interval.
#
# A killed agent never reaches this script. The ABSENCE of this line is what
# turns silence into an alert on the SIEM side.
$seq = 0
if (Test-Path 'C:\secwatch\seq.txt') { $seq = [int](Get-Content 'C:\secwatch\seq.txt' -ErrorAction SilentlyContinue) }
$line = "SECWATCH-SHUTDOWN seq=$seq reason=graceful host=$env:COMPUTERNAME"

try {
    $fs = [System.IO.File]::Open('C:\secwatch\events.log',
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::ReadWrite)
    $sw = New-Object System.IO.StreamWriter($fs)
    $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close()
} catch { }

# Give the agent time to ship the line before Windows tears down networking.
Start-Sleep -Seconds 8
