# 🛡️ Threat Hunt Report // Just Another Day

### Nimbus Health // A Routine Posture Review That Turns Out To Be Anything But

---

## 📌 Executive Summary

Nimbus Health, a small outpatient clinic, requested a posture review after a billing analyst account (`j.morris`) showed anomalous activity. The engagement was framed as a stale access housekeeping check, but the telemetry told a different story. This was an external operator driving `j.morris` from source IP `193.36.225.245` via `RemoteInteractive` RDP sessions, holding valid credentials for both `j.morris` (submissions) and `d.patel` (reviewer). Over the course of 11 March 2026, the operator ran two rounds of native reconnaissance on the billing workstation, reached into the `Approved` sign off folder to open invoices, modified the workflow audit trail to cover reviewer style activity under a submitter's session, staged HR compensation material (payroll and awards records) back into the Billing share under camouflaged names with double `.txt` extensions, and RDP pivoted onward to the file server and IT workstation. The IT hop showed only Windows profile initialization, a landing with no operator activity, absence as a finding. On the file server the operator ran a privilege check, enumerated shares, and opened another employee's payroll review file.

The evidence rules out both a routine insider mistake (deliberate cross department targeting with account switching between `j.morris` and `d.patel` from the same workstation within milliseconds) and malware (no execution, no dropped binaries, no exploitation, no C2). The honest root cause is credential compromise and hands on keyboard operation by an external actor working through a remote session from a non Nimbus workstation.

---

## 🗂️ Environment

**Organization:** Nimbus Health (outpatient clinic)
**Platform:** Windows estate (billing, HR, IT, file server, domain controller)
**Telemetry:** Microsoft Sentinel // MDE tables (`DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents`)
**Scope:** `nh-*` hosts only
**Window:** 08 to 18 March 2026 (primary activity on 11 March 2026)

*Note: There is a separate, later incident on the same estate. Every query is bounded to the March window and `nh-*` hosts to avoid crossing streams.*

---

## 🎯 Hunt Stages

*[ gate + 6 phases, 20 flags total ]*

| Stage | Focus |
|---|---|
| 00 | Setup gate |
| 01 | The billing account |
| 02 | Hands on the keyboard |
| 03 | Past the role |
| 04 | Moving through the network |
| 05 | Collection |
| 06 | Judgement |

---

## 🚩 Flag by Flag Findings

### Stage 01 // The Billing Account

*The account under review, how it is being used, and the part that does not fit an insider.*

---

**Flag 1: The Account Under Review**

> HUNT LEAD: *"The review flagged one billing account behaving oddly. Name it. That's who you're following."*

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-03-08) .. datetime(2026-03-19))
| where DeviceName startswith "nh-"
| where AccountName == "billing_analyst_account_name_here"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, RemoteDeviceName
| order by Timestamp asc
```

Investigation started against every device in the billing department. Reviewing the logs, several attempts to log in were followed by a successful logon at 2026-03-09T01:30:31 UTC with `IsLocalLogon: false`. That flag confirmed the successful session came from a remote source rather than a user sitting at the billing desk, and the account driving it was `j.morris`. That is who the rest of the hunt follows.

![flag1]<img width="1513" height="825" alt="image" src="https://github.com/user-attachments/assets/94a0de26-4cb7-4f66-b0db-9e1baf9f918b" />


**Answer:** `j.morris`

---

**Flag 2: How the Account Is Being Used**

> HUNT LEAD: *"This account isn't being used by someone sitting at the billing desk. Its successful sessions are a different kind of logon entirely. Give me the logon type."*

```kql
DeviceLogonEvents
| where DeviceName startswith "nh-"
| where Timestamp >= datetime(2026-03-09T01:00:00Z) and Timestamp <= datetime(2026-03-09T05:00:00Z)
| where AccountName contains "j.morris"
| where ActionType contains "Success"
| summarize count() by LogonType
```

Grouping the successful logon events for `j.morris` by `LogonType` isolated the logon method used across every successful session. `Network` was ruled out because the successful logons carried an external source. Between `Batch` and `RemoteInteractive`, `RemoteInteractive` fit the pattern of RDP sessions coming into the estate from outside the clinic network.

![flag2]<img width="828" height="692" alt="image" src="https://github.com/user-attachments/assets/47c35b62-9aaa-478b-b8cf-d0b5a4b297db" />


**Answer:** `RemoteInteractive`

---

**Flag 3: Where the Sessions Come From**

> HUNT LEAD: *"Here's what should stop you. Those remote sessions into the billing workstation are not coming from inside the clinic. Give me one of the sources they're coming from, and satisfy yourself it isn't an internal address."*

```kql
DeviceLogonEvents
| where DeviceName startswith "nh-"
| where AccountName contains "j.morris"
| where ActionType contains "success"
| project Timestamp, RemoteIP
```

Scoping `j.morris` successful logons to the `RemoteIP` field showed the external source of every remote interactive session. The IP `193.36.225.245` is a public address that does not fall within any of the internal `10.x` ranges observed on the Nimbus estate, confirming the session origin was external, not a misclassified internal device.

![flag3](screenshots/flag3.png)

**Answer:** `193.36.225.245`

---

### Stage 02 // Hands on the Keyboard

*The noise to rule out, then the real recon and what it was aimed at.*

---

**Flag 4: Signal or Noise**

> HUNT LEAD: *"Sort the account's command-shell activity by time and the first thing you'll hit is a burst of deletions. Before you build a theory on it, tell me, is that the intruder, or is it noise. And say how you know."*

```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where AccountName contains "j.morris"
| project Timestamp, AccountDomain, AccountName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine
```

Sorting by time surfaces a burst of file deletions on the billing workstation at the top of the results. Two fields rule these out as operator activity: `InitiatingProcessAccountName` is `system`, not `j.morris`, and `IsInitiatingProcessRemoteSession` is `false`. That combination proves the deletions were driven by a local system context, not by a remote human session. Machine housekeeping, not the intruder.

![flag4](screenshots/flag4.png)

**Answer:** `noise, the deletions were driven by the system account, not the remote operator`

---

**Flag 5: Getting Their Bearings**

> HUNT LEAD: *"Past the noise, the account's operator runs a short, deliberate burst of native commands to get their bearings. Give me that sequence, in order."*

```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where AccountName contains "j.morris"
| where InitiatingProcessAccountName == "j.morris"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

Filtering to processes initiated by `j.morris` (not `system`) surfaced a tight burst of native discovery commands at 2026-03-11T12:42:12 UTC. The operator ran identity checks (`whoami`, `hostname`), then session and network view enumeration (`net use`, `net view`), then closed with an explicit `net view \\NH-FS-01` naming the file server as a specific target. That last command flipped the recon from general discovery to targeted acquisition.

![flag5](screenshots/flag5.png)

**Answer:** `whoami, hostname, net use, net view, net view \\NH-FS-01`

---

**Flag 6: The Named Target**

> HUNT LEAD: *"The recon wasn't aimless. The last discovery command names one system specifically. Which server were they lining up?"*

```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where AccountName contains "j.morris"
| where InitiatingProcessAccountName == "j.morris"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

The final command in the recon burst was `net view \\NH-FS-01`, which enumerates the shares exposed by a single named host. That host, `NH-FS-01`, is the Nimbus file server, and the operator was lining it up as their next collection target before making any move toward it.

![flag6](screenshots/flag6.png)

**Answer:** `NH-FS-01`

---

**Flag 7: Widening the Net**

> HUNT LEAD: *"The operator came back to the shell a second time, later, and widened the net beyond the single server. One command asks the domain itself what's out there. Give it to me."*

```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where AccountName contains "j.morris"
| where InitiatingProcessAccountName == "j.morris"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

At 2026-03-11T13:17:35 UTC the operator returned to the shell and ran `net view /domain:nimbus`, which asks the domain controller for every host visible on the Nimbus domain. The shift from a single named server to the full domain view marks the escalation from targeted recon to broad estate enumeration.

![flag7](screenshots/flag7.png)

**Answer:** `"net.exe" view /domain:nimbus`

---

**Flag 8: Mapping Before the Jump**

> HUNT LEAD: *"Straight after the domain check, they spend two minutes building a picture of the local network, then immediately jump to another host. Tell me what they were doing in those two minutes, and why it comes right before the pivot."*

```kql
DeviceProcessEvents
| where DeviceName startswith "nh-"
| where AccountName != "system"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

Between 13:18:51 and 13:20:19 UTC the operator ran a sequence of `nslookup` reverse DNS lookups against internal IPs (`10.1.0.233`, `10.1.0.234`, `10.1.0.235`, `10.1.7.255`, `224.0.0.22`, `10.1.0.1`). Reverse DNS resolves an IP back to a hostname without touching the target host, quiet, no auth attempts, no port probes. This let the operator identify what each machine was (workstation, DC, file server) before choosing a target. Immediately after the sweep completed, they RDP'd into the domain controller, confirming the recon was silent target selection ahead of the pivot.

![flag8](screenshots/flag8.png)

**Answer:** `reverse DNS reconnaissance with nslookup, RDP pivot to the domain controller (nh-dc-01)`

---

### Stage 03 // Past the Role

*Reaching beyond the billing role, and the sensitive material moved under cover.*

---

**Flag 9: Out of Role**

> HUNT LEAD: *"A billing analyst on submissions has no business in the sign-off stage. But this account went there. Name the billing workflow folder it reached into that its role shouldn't touch."*

```kql
DeviceFileEvents
| where DeviceName == "nh-wks-bill-01.corp.nimbushealth.com"
| where FolderPath startswith "\\\\NH-FS-01\\Billing"
| where InitiatingProcessAccountName in ("j.morris", "d.patel")
| project Timestamp, InitiatingProcessAccountName, ActionType, FolderPath, FileName
| order by Timestamp asc
```

The billing workflow has two stages under `\\NH-FS-01\Billing\2026-03\`: `Pending` (submissions, where `j.morris` legitimately works) and `Approved` (sign off stage, meant for reviewers). The compromised `j.morris` account never wrote to `Approved` directly, but the same workstation (`nh-wks-bill-01`) shows `d.patel` writing to `Approved` within seconds of `j.morris` writing to `Pending`, sometimes under 40 seconds apart. That interleaving between two distinct user accounts on a single host is not achievable by one human hand switching sessions, it is the signature of a single operator holding valid credentials for both accounts and using each for whichever workflow stage it is authorized on.

![flag9](screenshots/flag9.png)

**Answer:** `Approved`

---

**Flag 10: The Invoice**

> HUNT LEAD: *"Inside that folder, name the invoice this account handled."*

```kql
union DeviceFileEvents, DeviceProcessEvents
| where FileName has "INV-664215" or FileName has "INV-773221" or ProcessCommandLine has "INV-664215" or ProcessCommandLine has "INV-773221"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, ProcessCommandLine, ActionType
| order by Timestamp asc
```

`j.morris` opened `approved_pending_invoice_INV-664215_20260310.txt` from `\\NH-FS-01\Billing\2026-03\Approved\` using notepad at 12:10:57 UTC on 11 March, followed 13 seconds later by a `FileModified` event on the same file at the file server. A second invoice, `approved_pending_invoice_INV-773221_20260311.txt`, was opened and renamed moments later. Both invoices live in the sign off stage folder outside `j.morris`'s submissions role. The extension was the trap on this flag, notepad opened `.txt` files, not the `.csv` the rest of the Billing share uses, so the on disk filename ends in `.txt` and the shortcut in `Recent` strips the extension.

![flag10](screenshots/flag10.png)

**Answer:** `approved_pending_invoice_INV-664215_20260310.txt`

---

**Flag 11: The Audit Trail**

> HUNT LEAD: *"The account also touched the workflow's audit trail, the record that's supposed to reflect the reviewer's actions, not a submitter's. Name the audit file it modified."*

```kql
DeviceFileEvents
| where DeviceName startswith "nh-"
| where InitiatingProcessAccountName contains "system"
| where ActionType contains "modified"
| where FileName contains "audit"
| project Timestamp, ActionType, InitiatingProcessAccountName, FileName, FolderPath
```

`j.morris` modified `review_audit_20260311.txt` on the file server, the workflow's audit trail file that records reviewer actions on the sign off stage. Because the write to the FS was carried out by the `system` account on `nh-fs-01` over SMB, the modification only surfaces cleanly by filtering on the FS system context rather than the initiating user. The audit trail is designed to log reviewer activity like `d.patel`'s, so a modification driven from a submitter's session is direct evidence of the operator falsifying or covering the workflow record.

![flag11](screenshots/flag11.png)

**Answer:** `review_audit_20260311.txt`

---

**Flag 12: Staged Under Cover**

> HUNT LEAD: *"This is the one that matters. The account pulled payroll material out of HR and dropped it into the billing share, renamed to look like a billing exception, so it would sit there without raising an eyebrow. Name the payroll file as it ended up in the billing folder."*

```kql
DeviceFileEvents
| where DeviceName startswith "nh-"
| where FolderPath contains "Billing"
| where FileName has_any ("exception", "payroll", "hr_", "compensation", "salary")
| project Timestamp, ActionType, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine
```

Searching the Billing share for files whose names read like exceptions or HR content surfaced a file named `payroll_exception_reference_20260311.txt.txt`. The double `.txt.txt` extension is the tell. A quick visual pass reads it as a single `.txt` and slides past the doubled suffix, exactly the "sit there without raising an eyebrow" camouflage the hunt lead flagged. The operator pulled payroll material out of HR, renamed it to look like a routine billing exception reference, and staged it inside the Billing share where its presence would not draw a second look.

![flag12](screenshots/flag12.png)

**Answer:** `payroll_exception_reference_20260311.txt.txt`

---

**Flag 13: The Second Target**

> HUNT LEAD: *"Payroll wasn't the only thing they took from HR. In the same burst, they touched a second HR file that has nothing to do with payroll. Name it, and note what it tells you about the scope."*

```kql
DeviceFileEvents
| where DeviceName startswith "nh-"
| where FolderPath contains "Billing"
| where FileName has_any ("exception", "payroll", "hr_", "compensation", "salary", "awards", "merit")
| project Timestamp, ActionType, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine
```

The same query pattern surfaced a second file with the same double `.txt` extension trick, staged shortly before the payroll file. `quarterly_awards_shortlist_20260310.txt` was pulled from an HR awards folder, unrelated to payroll but still sensitive HR material identifying employees selected for recognition and their proposed rewards. Two files from two distinct HR functions (compensation and awards), staged in the Billing share under camouflage, means the collection is broader than a single payroll incident, it is a systematic sweep of HR review artifacts.

![flag13](screenshots/flag13.png)

**Answer:** `quarterly_awards_shortlist_20260310.txt`

---

### Stage 04 // Moving Through the Network

*The onward hops, and the one that turns out to be a red herring.*

---

**Flag 14: The Onward Hops**

> HUNT LEAD: *"They didn't stop at the billing box. From there the account opened remote sessions onto two more machines. Name both."*

```kql
DeviceLogonEvents
| where DeviceName startswith "nh-"
| where AccountName == "j.morris"
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where DeviceName != "nh-wks-bill-01.corp.nimbushealth.com"
| project Timestamp, DeviceName, RemoteIP, AccountName, LogonType
| order by Timestamp asc
| distinct DeviceName
```

Filtering `j.morris` successful `RemoteInteractive` logons to hosts other than the billing workstation returned two additional targets: `nh-fs-01` (the file server) and `nh-wks-it-01` (the IT workstation). The `RemoteIP` on both pivot logons resolved to `nh-wks-bill-01`'s internal address, confirming the sessions were internal hops from the billing workstation the operator already held, not fresh external logons.

![flag14](screenshots/flag14.png)

**Answer:** `nh-fs-01.corp.nimbushealth.com, nh-wks-it-01.corp.nimbushealth.com`

---

**Flag 15: The Red Herring**

> HUNT LEAD: *"One of those two hops is a red herring, and I want you to prove it rather than assume it. They landed on the IT workstation. Did they actually do anything there? Check, and tell me what you found."*

```kql
DeviceFileEvents
| where DeviceName has_any ("nh-wks-it-01.corp.nimbushealth.com", "nh-fs-01.corp.nimbushealth.com")
| project Timestamp, ActionType, DeviceName, FileName
```

Comparing the two pivot targets side by side made the split obvious. On `nh-wks-it-01` the only activity was standard Windows first logon profile initialization (`Explorer.EXE`, `unregmp2.exe /FirstLogon`, `ie4uinit.exe`, `WininetPlugin.dll` cache migration, Edge `setup.exe`), the noise every fresh user profile generates when it initializes on a Windows host. No commands, no file opens, no lateral movement onward. On `nh-fs-01`, by contrast, there was operator driven activity including native discovery commands and text files consistent with hands on collection. The IT box was a landing without follow through, the file server was where the actual work happened.

![flag15-1](screenshots/flag15-1.png)

![flag15-2](screenshots/flag15-2.png)

**Answer:** `no hands on keyboard activity, only Windows profile initialization`

---

### Stage 05 // Collection

*What the account did once it reached the file server, and whose data it took.*

---

**Flag 16: Checking Their Rights**

> HUNT LEAD: *"On the file server, the account's operator ran a command to check what privileges and groups they had. Give me it."*

```kql
DeviceProcessEvents
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

On the file server, `j.morris` ran `whoami.exe /groups`, which enumerates the security groups the account belongs to on the target host. This is the same discovery pattern the operator used on the billing workstation, checking group membership before deciding what to touch. On a file server specifically, the group check confirms whether the account carries the permissions needed to browse shares and read protected data.

![flag16](screenshots/flag16.png)

**Answer:** `"whoami.exe" /groups`

---

**Flag 17: What the Server Offered**

> HUNT LEAD: *"Right after the privilege check, they enumerated what the file server was offering. Give me that command."*

```kql
DeviceProcessEvents
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

Directly after the privilege check, the operator ran `net.exe share`, which lists every share the file server is exposing along with their paths and permissions. Combining the privilege check with a share enumeration gave the operator a full picture: what they were authorized to do, and where the sensitive shares were mounted.

![flag17](screenshots/flag17.png)

**Answer:** `"net.exe" share`

---

**Flag 18: Someone Else's Payroll**

> HUNT LEAD: *"The last thing they did on the file server was open a payroll review belonging to a different employee entirely. Name the file, and note whose it is."*

```kql
DeviceProcessEvents
| where DeviceName == "nh-fs-01.corp.nimbushealth.com"
| where AccountName == "j.morris"
| project Timestamp, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

The last action on the file server was opening `payroll_review_dpatel_20260311.txt`, a payroll review file belonging to `d.patel`, the same reviewer account the operator was already driving in parallel on the billing workstation. The operator used `j.morris`'s file server session to read `d.patel`'s payroll review, confirming they were interested not just in the reviewer's permissions but in the reviewer's personal compensation record. The same filename also appears staged locally at `C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt`, showing the file was pulled down to the billing workstation's user folder as a working copy.

![flag18](screenshots/flag18.png)

**Answer:** `payroll_review_dpatel_20260311.txt (belongs to d.patel, the reviewer account also driven by the operator)`

---

### Stage 06 // Judgement

*The scope of the theft, and the honest root cause the evidence supports.*

---

**Flag 19: What Else Left HR**

> HUNT LEAD: *"Step back over the HR collection. Beyond the one payroll file everyone notices, how would you characterise what this account took out of HR? Give me the scope in a sentence."*

The HR collection was not a single payroll file, it was a cross section of the entire compensation cycle. `Recent` folder shortcuts on `nh-wks-bill-01` show `j.morris` opened `compensation_change_log_20260310`, `Compensation`, `merit_increase_review_20260309`, `temp_payroll_review_jmorris_20260311.txt`, `Payroll`, `quarterly_awards_shortlist_20260310`, and `Awards`, each a distinct document type from a different corner of the HR compensation workflow. Together they map current pay changes, upcoming merit adjustments, quarterly award decisions, and payroll reviews for individual employees. This is not opportunistic browsing, it is a deliberate sweep of the workforce's compensation posture across every stage of the cycle.

*(No screenshot for this flag, scope was reasoned across the full HR file access pattern rather than from a single query view.)*

**Answer:** `A cross section of the HR compensation cycle: pay changes, merit reviews, awards, and payroll data, not one file but the whole compensation posture.`

---

**Flag 20: The Honest Read**

> HUNT LEAD: *"The clinic will want to write this up as a curious employee with leftover access. You've seen the evidence. Give me the honest read. What actually happened here, and what's missing that tells you it wasn't malware and wasn't a routine insider mistake?"*

This was not a curious insider, and it was not malware. The account was driven from a remote workstation outside the Nimbus estate (identifiable through the `RemoteSessionDeviceName` field on the interactive logons), by an operator holding valid credentials for at least two accounts, `j.morris` (submissions) and `d.patel` (reviewer). The same operator switched between them within milliseconds on the same billing workstation to write claims into whichever workflow stage each account was authorized on. That coordinated cross account behavior is not something a routine insider mistake produces. On the malware side, the absence is the finding: no execution of any dropped binaries, no exploitation, no exfiltration over an external C2, no defense tampering. Every action was carried out with native Windows binaries under valid credentials, the Living off the Land signature of an external actor abusing valid access rather than a payload delivered attack.

*(No screenshot for this flag, judgement was reasoned across the full timeline.)*

**Answer:** `Remote session operator driving j.morris from an external workstation; no malware or exploitation present, but deliberate cross department pivoting and credential switching between j.morris and d.patel rules out an insider mistake.`

---

## 🕒 Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 09 March 01:30:31 | nh-wks-bill-01 | First successful `RemoteInteractive` logon by j.morris from external IP 193.36.225.245 (Flag 1, 2, 3) |
| 11 March 12:06:33 | nh-fs-01 | j.morris creates legitimate `pending_claim_CLM-643215_20260311.csv` in Pending folder |
| 11 March 12:10:57 | nh-wks-bill-01 | j.morris opens `approved_pending_invoice_INV-664215_20260310.txt` via notepad (out of role) (Flag 10) |
| 11 March 12:11:10 | nh-fs-01 | INV-664215 modified on FS (system context) |
| 11 March 12:11:49 | nh-fs-01 | INV-773221 renamed |
| 11 March 12:11:56 | nh-wks-bill-01 | j.morris opens INV-773221 via notepad |
| 11 March 12:12:16 | nh-fs-01 | INV-773221 modified on FS |
| 11 March ~12:46 to 13:00 | nh-wks-bill-01 | HR file access burst: compensation_change_log, Compensation, merit_increase_review, temp_payroll_review_jmorris, Payroll, quarterly_awards_shortlist, Awards (Flag 19) |
| 11 March 12:42:12 | nh-wks-bill-01 | First recon burst: whoami, hostname, net use, net view, net view \\NH-FS-01 (Flag 5, 6) |
| 11 March 13:17:35 | nh-wks-bill-01 | Second recon: `net view /domain:nimbus` (Flag 7) |
| 11 March 13:18:51 to 13:20:19 | nh-wks-bill-01 | Nslookup reverse DNS sweep across internal IPs (Flag 8) |
| 11 March 13:25:16 | nh-wks-bill-01 | `mstsc /v:10.1.0.235` (RDP to file server target) |
| 11 March 13:25:31 | nh-dc-01 / nh-fs-01 | Session initialization observed at pivot target |
| 11 March 13:26:54 | nh-wks-bill-01 | `mstsc /v:10.1.0.233` (RDP to IT workstation) |
| 11 March 13:27:08 to 13:27:11 | nh-wks-it-01 | Windows profile initialization only, no operator activity (Flag 14, 15 red herring) |
| 11 March (session) | nh-fs-01 | j.morris runs `whoami /groups` on file server (Flag 16) |
| 11 March (session) | nh-fs-01 | j.morris runs `net share` to enumerate shares (Flag 17) |
| 11 March (session) | nh-fs-01 | j.morris opens `payroll_review_dpatel_20260311.txt` (Flag 18) |
| 11 March (staging) | nh-fs-01 → Billing | `payroll_exception_reference_20260311.txt.txt` staged in Billing share under camouflage (Flag 12) |
| 11 March (staging) | nh-fs-01 → Billing | `quarterly_awards_shortlist_20260310.txt` staged in Billing share (Flag 13) |
| 11 March (session) | nh-fs-01 | `review_audit_20260311.txt` modified to log reviewer style actions from submitter session (Flag 11) |
| 11 March (parallel) | nh-wks-bill-01 | d.patel writes `approved_pending_claim_*.csv` files into Approved within seconds of j.morris writes into Pending (Flag 9) |

---

## 🧭 MITRE ATT&CK Mapping

| Flag | Tactic | Technique |
|---|---|---|
| 1 | Initial Access | T1078 Valid Accounts (account identification) |
| 2 | Initial Access | T1078 Valid Accounts, T1021.001 Remote Services: Remote Desktop Protocol |
| 3 | Initial Access | T1078 Valid Accounts, T1133 External Remote Services |
| 4 | (Analyst Discrimination) | Signal vs noise separation, no attacker technique |
| 5 | Discovery | T1033 System Owner/User Discovery, T1082 System Information Discovery, T1135 Network Share Discovery |
| 6 | Discovery | T1135 Network Share Discovery |
| 7 | Discovery | T1018 Remote System Discovery |
| 8 | Discovery, Lateral Movement | T1018 Remote System Discovery, T1021.001 Remote Services: RDP |
| 9 | Collection | T1039 Data from Network Shared Drive, T1078 Valid Accounts (account misuse) |
| 10 | Collection | T1039 Data from Network Shared Drive, T1005 Data from Local System |
| 11 | Defense Evasion | T1070 Indicator Removal (audit log tampering) |
| 12 | Collection, Defense Evasion | T1074.001 Local Data Staging, T1036.005 Masquerading: Match Legitimate Name or Location |
| 13 | Collection, Defense Evasion | T1074.001 Local Data Staging, T1036.005 Masquerading |
| 14 | Lateral Movement | T1021.001 Remote Services: RDP |
| 15 | (Analyst Discrimination) | Absence as finding, no attacker technique |
| 16 | Discovery | T1069.001 Permission Groups Discovery: Local Groups |
| 17 | Discovery | T1135 Network Share Discovery |
| 18 | Collection | T1039 Data from Network Shared Drive, T1005 Data from Local System |
| 19 | Collection | T1213 Data from Information Repositories, T1039 |
| 20 | (Overall Model) | T1078 Valid Accounts + T1059 Command and Scripting Interpreter (Living off the Land) |

---

## 🔑 Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| IP | 193.36.225.245 | External attacker source for RemoteInteractive RDP into nh-wks-bill-01 |
| Account | j.morris | Compromised billing analyst account (primary session) |
| Account | d.patel | Compromised reviewer account (used in parallel from same workstation) |
| Host | nh-wks-bill-01 | Primary compromised workstation, operator's foothold |
| Host | nh-fs-01 | File server, source of HR collection and audit trail tampering |
| Host | nh-wks-it-01 | RDP landing target, red herring, no operator activity |
| File | approved_pending_invoice_INV-664215_20260310.txt | Invoice opened out of role from Approved folder |
| File | approved_pending_invoice_INV-773221_20260311.txt | Second invoice opened, renamed on FS |
| File | review_audit_20260311.txt | Workflow audit trail modified from submitter session |
| File | payroll_exception_reference_20260311.txt.txt | Payroll data staged in Billing share under double .txt camouflage |
| File | quarterly_awards_shortlist_20260310.txt | HR awards data staged in Billing share |
| File | payroll_review_dpatel_20260311.txt | Reviewer's personal payroll record accessed and staged locally |
| Path | C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt | Local working copy on billing workstation |
| Pattern | Double `.txt.txt` extension in Billing share | Renamed HR files masquerading as billing text files |
| Pattern | Sub second interleaving of j.morris (Pending) and d.patel (Approved) writes from single workstation | Signature of single operator holding both credentials |
| Pattern | RemoteInteractive session from external IP not matching any Nimbus asset | Origin telemetry for identifying operator sessions |

---

## ⚖️ Judgement & Response

**Attack chain:**
External RDP entry using valid j.morris credentials from 193.36.225.245 → out of role invoice access and audit trail tampering on Approved folder → HR compensation collection across multiple document types → data staged back into Billing share under double .txt camouflage → RDP pivot to file server for hands on collection → parallel d.patel session used to make cross stage writes (Pending / Approved) look like normal workflow activity → cross employee payroll record accessed on file server → RDP landing on IT workstation with no follow through (red herring).

**What really happened:**

This was a valid credential compromise, not an exploit chain and not an insider mistake. An external operator, connecting from `193.36.225.245` via `RemoteInteractive` RDP into `nh-wks-bill-01`, held credentials for at least two Nimbus accounts: `j.morris` (billing analyst on the submissions side of the billing workflow) and `d.patel` (a reviewer with sign off permissions on the Approved stage). The operator used both accounts in parallel from the same workstation, switching between them within milliseconds to write files into whichever workflow stage each account was authorized on, `j.morris` into `Pending`, `d.patel` into `Approved`, making the workflow look like normal review activity.

Under `j.morris` they ran two rounds of native reconnaissance (`whoami`, `hostname`, `net use`, `net view`, then `net view /domain:nimbus`, then a reverse DNS sweep with `nslookup`), opened invoices in the Approved sign off folder they had no legitimate business touching, and modified the `review_audit_20260311.txt` file to log reviewer style actions from a submitter's session. They then pulled HR compensation material across the entire compensation cycle (payroll, merit increases, awards shortlists, individual payroll reviews) and staged two of those files back into the Billing share under masqueraded filenames using a double `.txt.txt` extension trick to blend into billing content. They RDP'd to the file server, ran a privilege and share enumeration burst, and opened `d.patel`'s own payroll review file, pulling a local working copy onto the billing workstation. A separate RDP landing on the IT workstation produced only Windows profile initialization events with no operator activity, absence as a finding.

**How it was hidden:**

- Same valid privileged accounts as real employees, so every action looked like ordinary admin or clerical work in the auth telemetry.
- Credential switching between `j.morris` and `d.patel` from the same workstation covered both workflow stages, no ACL had to be violated.
- Files staged in Billing share used a double `.txt.txt` extension that reads as a single `.txt` on visual scan, camouflaging HR content inside role appropriate storage.
- Audit trail modified from a submitter's session to reflect reviewer style actions, hiding the workflow anomaly at the record level.
- RDP landing on IT workstation produced only profile initialization noise, decoy activity that reads like additional lateral movement without generating any real evidence to follow.
- No malware execution, no dropped binaries, no exploitation, no external C2, purely a Living off the Land operation using native Windows tooling under valid credentials.
- Operator source IP `193.36.225.245` is external but the actual driving workstation surfaces only through the `RemoteSessionDeviceName` field, not the primary logon telemetry, requiring analysts to know to check for it.

**Response actions (NIST SP 800-61):**

*Containment:*
- Disable `j.morris` and `d.patel` across Entra ID and local Active Directory
- Force logoff of all active sessions on `nh-wks-bill-01`, `nh-fs-01`, `nh-wks-it-01`, and `nh-dc-01`
- Block `193.36.225.245` at perimeter firewall
- Block `*.corp.nimbushealth.com` external RDP for all accounts pending MFA rollout
- Isolate `nh-wks-bill-01` and `nh-fs-01` from network pending eradication

*Eradication:*
- Delete staged files from Billing share: `payroll_exception_reference_20260311.txt.txt` and `quarterly_awards_shortlist_20260310.txt`
- Delete local working copy `C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt`
- Restore `review_audit_20260311.txt` from clean backup (pre 11 March 2026) and verify integrity of all audit records in the sign off workflow
- Reset passwords for `j.morris` and `d.patel`, and audit for any other accounts recently authenticated from `193.36.225.245`
- Review `nh-dc-01` for any changes made during the DC pivot session, particularly around group membership and delegated permissions
- Confirm `nh-wks-it-01` was truly untouched beyond the profile initialization (verify absence of writes, since reads alone would not surface in `DeviceFileEvents`)

*Recovery:*
- Rebuild `nh-wks-bill-01` and `nh-fs-01` from clean baselines rather than trusting cleanup, since persistence outside the discovered artifacts cannot be fully ruled out
- Restore any impacted HR or billing data from clean pre 11 March backups
- Notify affected employees whose compensation data was accessed, particularly `d.patel` whose personal payroll review was staged
- Assess HIPAA and PII notification obligations given the healthcare context and the scope of compensation data touched
- Reintroduce hosts to network under enhanced monitoring

*Lessons Learned:*
- Enforce MFA on all external RDP, including for standard user accounts like billing analysts, this intrusion would not have been possible with MFA in place
- Implement Conditional Access to block RDP from unrecognized geographies or non domain joined workstations
- Alert on `RemoteSessionDeviceName` values that do not match known corporate assets, this field was the tell for the external operator workstation
- Segregate duty enforcement between `Pending` and `Approved` folder ACLs so no single workstation can produce writes into both stages within seconds
- Alert on file staging patterns: double extensions in shares, and HR filename patterns appearing in Billing storage
- Alert on audit trail modifications originating from accounts that are not in the reviewer group
- Baseline behavior for billing accounts: any RDP from a workstation subnet to the DC or file server should trigger alerts as it falls outside normal billing analyst duties
- HR share access should require additional authentication or DLP inspection for reads originating from non HR subnets

---

## 📎 Repository Notes

- Screenshots for each flag are in `/screenshots/` named `Flag [N].png`
- Flags 19 and 20 have no screenshots as findings were reasoned across the full HR access pattern and full timeline synthesis rather than from a single query view
- All queries are scoped to `DeviceName startswith "nh-"` and the March 2026 window to isolate this hunt from the separate later incident on the same estate
