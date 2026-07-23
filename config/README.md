# Configuration notes

Reference configs and the exact steps used to build the lab.

## Files

| File | Purpose |
|------|---------|
| [`sysmon-localfile.xml`](sysmon-localfile.xml) | The `<localfile>` block added to the Windows agent's `ossec.conf` so Wazuh collects the Sysmon channel. |
| [`attack-simulation.md`](attack-simulation.md) | The exact commands used to generate each detection. |

## Component versions

| Component | Version / detail |
|-----------|------------------|
| Wazuh (manager + dashboard) | 4.14.6 |
| Wazuh manager host | Ubuntu Server — `192.168.64.134` |
| Endpoint | Windows 11 Pro (`Win11-Victim`, agent 001) — `192.168.64.132` |
| Sysmon | v15.21 |
| Sysmon config | SwiftOnSecurity `sysmonconfig-export.xml` |
| Hypervisor | VMware Workstation Pro (host-only isolated network) |

## Build steps (summary)

1. **Deploy Wazuh** on the Ubuntu Server VM (all-in-one installer); log in to the dashboard over HTTPS.
2. **Onboard the Windows endpoint** — install the Wazuh agent, enroll to the manager, confirm **Active**.
3. **Install Sysmon** with the SwiftOnSecurity config:
   ```powershell
   .\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
   Get-Service Sysmon64        # should report Running
   ```
4. **Forward Sysmon to Wazuh** — add [`sysmon-localfile.xml`](sysmon-localfile.xml) to `ossec.conf`, then:
   ```powershell
   Restart-Service WazuhSvc
   ```
5. **Verify** telemetry with the dashboard filter:
   ```
   data.win.system.providerName: "Microsoft-Windows-Sysmon"
   ```
6. **Generate & investigate** the detections in [`attack-simulation.md`](attack-simulation.md).
