# Architecture

## Log pipeline

```
  ┌─────────────────────────────────────────────────────────┐
  │        Ubuntu Server — Wazuh Manager (192.168.64.134)    │
  │        Manager  +  Indexer  +  Dashboard                 │
  └───────────────────────────▲─────────────────────────────┘
                              │  encrypted agent traffic (TCP/1514)
                              │
  ┌───────────────────────────┴─────────────────────────────┐
  │   Windows 11 Endpoint — "Win11-Victim" (192.168.64.132)  │
  │                                                          │
  │   ┌────────────┐   ┌───────────────────────┐            │
  │   │  Sysmon    │   │  Windows Security Log  │            │
  │   │  v15.21    │   │  (4720 / 4732 / 4625)  │            │
  │   └─────┬──────┘   └───────────┬───────────┘            │
  │         │                      │                        │
  │         └──────► Wazuh Agent ◄─┘                        │
  └───────────────────────────▲─────────────────────────────┘
                              │  simulated attacker activity
                              │  (run locally on the endpoint)
                      ⚔️  net.exe / PowerShell
```

## Network

- VMs run on a **VMware host-only / internal network**, isolated from the home LAN.
- The agent ships events to the manager over **encrypted TCP/1514**.
- Manager: `192.168.64.134` · Endpoint: `192.168.64.132`.

## Data sources

| Source | What it provides | Example events used |
|--------|------------------|---------------------|
| Windows Security log | Account & logon auditing | 4720 (user created), 4732 (added to group), 4625 (failed logon) |
| Sysmon (SwiftOnSecurity) | Process, network, file telemetry | Event ID 1 (process create), Event ID 11 (file create) |

> A rendered diagram image (draw.io / Excalidraw) can be dropped in here as `architecture.png` and
> referenced from the top-level README if you prefer a graphic to the ASCII/Mermaid versions.
