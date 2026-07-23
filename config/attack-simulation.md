# Attack Simulation — exact commands used

All "attacker" activity was generated **locally on the Windows 11 endpoint** (`Win11-Victim`) from an
**elevated PowerShell** prompt. No separate attacker VM was required — this keeps the lab light on
disk/RAM while still producing realistic, high-signal detections.

> ⚠️ These commands are for an **isolated lab you own**. Do not run them on production systems.

---

## Detection 1 — Rogue local admin account (T1136 / T1098)

```powershell
net user hacker P@ssw0rd123! /add
net localgroup administrators hacker /add
```

**Cleanup:**
```powershell
net localgroup administrators hacker /delete
net user hacker /delete
```

Fires: rule `60154` (Administrators Group Changed, level 12) + account-creation chain.
See [investigation 01](../investigations/01-rogue-admin-account.md).

---

## Detection 2 — Brute-force / password spray (T1110)

A **fake** username is used so no real account is locked out.

```powershell
$p = ConvertTo-SecureString "WrongPass123!" -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential("evilhacker",$p)
1..12 | ForEach-Object { try { Start-Process cmd.exe -Credential $c -ErrorAction Stop } catch {} }
```

Fires: 12× rule `60122` (level 5) correlated into rule `60204` (Multiple Windows Logon Failures,
level 10). See [investigation 02](../investigations/02-brute-force-logins.md).

---

## Detection 3 — Obfuscated PowerShell (T1059.001)

```powershell
$cmd = 'Write-Host "simulated suspicious command"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -nop -w hidden -enc $enc
```

Fires: rule `92027` (PowerShell spawned PowerShell, level 4) + a level-15 `92213` that is triaged as a
**false positive**. See [investigation 03](../investigations/03-obfuscated-powershell.md).
