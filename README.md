# azure-arc-kql-detection-lab

> **Hybrid security logging & detection pipeline connecting on-premises Windows endpoints to Azure Arc, Log Analytics, and KQL for real-time audit querying and attack validation.**

---

```markdown
# 🛠️ Hybrid Infrastructure Management & Telemetry with Azure Arc and Log Analytics

## 📋 Summary
Design and implementation of a hybrid monitoring and audit logging infrastructure using **Azure Arc**, **Data Collection Rules (DCR)**, and a **Log Analytics Workspace**. The project integrates an on-premises server (`RASPUTIN_2025`) and a local workstation (`JACEK-WIN11`) into a unified cloud control plane for centralized security querying (KQL) and performance tracking — and validates the pipeline end-to-end with deliberately generated test events.

---

## 🏗️ Architecture Overview

```text
[ On-Premises Nodes ]                 [ Microsoft Azure Cloud ]
┌─────────────────────────┐           ┌─────────────────────────────────────────┐
│ RASPUTIN_2025           │           │ Data Collection Rule (DCR)              │
│ (Windows Server 2025)   ├──────┐    │ (dcr-windows2025-security)              │
└─────────────────────────┘      │    └────────────────────┬────────────────────┘
                                 ├──>                      │
┌─────────────────────────┐      │                         ▼
│ JACEK-WIN11             ├──────┘    ┌─────────────────────────────────────────┐
│ (Windows 11 Pro)        │           │ Log Analytics Workspace                 │
└─────────────────────────┘           │ (law-hybridsystem-lab)                  │
                                      └────────────────────┬────────────────────┘
                                                           │
                                                           ▼
                                      ┌─────────────────────────────────────────┐
                                      │ KQL Queries & Azure Monitor Dashboards  │
                                      └─────────────────────────────────────────┘

```

---

## 🚀 Key Implementation Steps

### 1. Hybrid Onboarding via Azure Arc

Deployed the `AzureConnectedMachineAgent` across both heterogeneous endpoints:

* **On-premises domain server:** `RASPUTIN_2025` (Windows Server 2025 Standard Evaluation)
* **Local client workstation:** `JACEK-WIN11` (Windows 11 Pro, non-domain-joined / WORKGROUP)

Successfully authenticated and registered both hosts into a dedicated Azure Resource Group (`rg-windows2025-arc`) in the `UK South` region. Both machines report `Connected` status in Azure Arc.

### 2. Telemetry & Audit Logging (Data Collection Rules)

Configured a custom Data Collection Rule (`dcr-windows2025-security`) to collect Windows Security and System Event Logs, streamed in real time into a central **Log Analytics Workspace** (`law-hybridsystem-lab`).

### 3. Performance Metrics Tracking

Enabled performance counter ingestion (CPU, Memory, Disk IOPS, Network Throughput, Latency, Logical Disk usage) across both managed nodes, with dashboards in **Azure Monitor**.

---

## 🧪 Detection Validation & Test Methodology

Configuring the infrastructure is only half the job — the pipeline needs to be proven to actually capture and ingest security events end-to-end. To do that, a controlled authentication failure was deliberately generated on `JACEK-WIN11`:

```cmd
net use \\localhost\c$ /user:test wrongpass

```

This attempts to map a network share using a local account (`test`) that does not exist on the machine, with a deliberately incorrect password — triggering a **Windows Security Event ID 4625** (failed logon) over the SMB/NTLM path.

### Technical Analysis of Log Ingestion Output

From the Log Analytics Workspace query output, matched against the corresponding local Event Viewer entry to confirm it was the actual test event (and not unrelated background noise):

* **Account For Which Logon Failed:** `test` (Account Domain: `-`) — the target account named in the command
* **Logon Type:** `3` (Network) — expected, since `net use` authenticates over SMB, not an interactive console logon
* **Source Network Address:** `::1` (IPv6 loopback), **Workstation Name:** `JACEK-WIN11`
* **Logon Process / Package:** `NtLmSsp` / `NTLM` — consistent with a loopback SMB authentication attempt
* **Status Code:** `0xC000006D` (`STATUS_LOGON_FAILURE`)
* **Sub Status Code:** `0xC0000064` (`STATUS_NO_SUCH_USER`) — the account name itself doesn't exist on the machine, distinct from *"correct username, wrong password"* (`0xC000006A`)

This confirms the custom DCR correctly captures, parses, and ingests security failures from a non-domain-joined Windows 11 endpoint in near real time (observed ingestion latency: a few minutes).

> 💡 **Noise vs. Signal:** While validating this, the workspace also surfaced a separate, recurring 4625 pattern unrelated to the test — Subject `JACEK-WIN11$` (the machine's own SYSTEM context, SID `S-1-5-18`), target account resolving to a `NULL SID`, source `127.0.0.1`, caller process `svchost.exe`, substatus `0xC0000380` (`STATUS_SMARTCARD_WRONG_PIN`). This turned out to be internally-generated background authentication noise (consistent with reports of the same pattern from other Windows 11/Server hosts), not an external or user-driven logon attempt. Distinguishing this from the actual test event was itself a useful exercise: it's exactly the kind of noise a SOC analyst has to filter out before treating a 4625 spike as a real signal.

---

## 🔍 Security Querying with KQL

### 1. Baseline Audit Query

Aggregating successful (`4624`) and failed (`4625`) logon events across all nodes:

```kql
Event
| where EventID in (4624, 4625)
| summarize Count=count() by Computer, EventID
| sort by Count desc

```

### 2. Detailed Failed-Logon Inspection

Extracting raw event descriptions and exact timestamps for detailed analysis:

```kql
Event
| where EventID == 4625
| project TimeGenerated, Computer, EventID, RenderedDescription
| sort by TimeGenerated desc

```

### 3. Advanced Correlation — Brute-Force Followed by Successful Logon

A single count query tells you activity happened; it doesn't tell you if it's a pattern worth investigating. This query bins failed and successful logons into 15-minute windows and joins them per host, as a lightweight signal for *"repeated failures followed by a successful logon on the same machine"*:

```kql
let FailedLogons = 
    Event
    | where EventID == 4625
    | summarize FailedCount = count() by Computer, bin(TimeGenerated, 15m);
let SuccessfulLogons = 
    Event
    | where EventID == 4624
    | summarize SuccessCount = count() by Computer, bin(TimeGenerated, 15m);
FailedLogons
| join kind=inner SuccessfulLogons on Computer, TimeGenerated
| project TimeGenerated, Computer, FailedCount, SuccessCount
| sort by TimeGenerated desc

```

#### Sample Output (from the test run against `JACEK-WIN11`):

| TimeGenerated (UTC) | Computer | FailedCount | SuccessCount |
| --- | --- | --- | --- |
| `2026-08-08T11:00:00Z` | `JACEK-WIN11` | `3` | `7` |

*In this case the failed/successful mix reflects the controlled test activity above rather than a genuine intrusion attempt — included here to demonstrate the query logic works and produces a readable, actionable result.*

> **Known limitation:** `bin(TimeGenerated, 15m)` combined with an `inner join` only correlates events that fall inside the same fixed 15-minute bucket. A failed logon at 11:14 and a successful one at 11:16 would land in different bins (11:00 and 11:15) and be missed by this join, even though they're only two minutes apart. Fine for a lab exercise; in production this would need a sliding window or a scheduled Sentinel alert rule with a proper lookback period.

---

## 📸 Screenshots & Proof of Work

* 🔗 [01_azure_arc_machines.png](img/01_azure_arc_machines.png) – Both endpoints showing `Connected` status with monitoring extension installed.
* 🔗 [02_kql_logon_audit.png](img/02_kql_logon_audit.png) – Baseline KQL query output aggregating logon events across both nodes.
* 🔗 [03_kql_failed_logon_detail.png](img/03_kql_failed_logon_detail.png) – Detailed 4625 output confirming DCR ingestion of controlled test failures.
* 🔗 [04_kql_correlation_query.png](img/04_kql_correlation_query.png) – Correlation query joining failed/successful logons in 15-minute windows.
* 🔗 [05_performance_monitoring.png](img/05_performance_monitoring.png) – Real-time disk IOPS, network traffic, and resource usage in Azure Monitor.

> **Note:** All screenshots have been anonymized prior to publishing to redact subscription IDs, tenant IDs, and personal account credentials.

---

## 💡 Key Learnings & Next Steps

* **Hybrid Operations:** Hands-on experience managing multi-node hybrid environments (domain-joined server + standalone workstation) without migrating workloads off-premises.
* **Verification over Assumption:** Configuring a DCR isn't proof it works — deliberately generating and confirming ingestion of specific event types (`4624`/`4625`) closed that gap.
* **Correlation over Raw Counting:** Moved from a flat count query to a join-based detection pattern, and identified its fixed-bin limitation rather than treating it as production-ready.
* **Next Steps:** Convert the correlation query into a **Microsoft Sentinel** scheduled analytics rule with a defined threshold and alert action; move to a sliding time window; enable **Microsoft Defender for Cloud** on both Arc-onboarded machines to extend the security posture beyond log collection.

```

```
