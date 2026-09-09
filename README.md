# OS Security Simulator: Windows vs. macOS Access Control

An educational Operating System Security Simulator that models and compares the authorization and access control architectures of **Microsoft Windows** and **Apple macOS**.

---

## What It Simulates

This project simulates how modern operating systems determine whether a process is allowed to read, write, execute, or delete a resource:

### 1. Windows Security Model (`windows_acl.c`)
Simulates Windows NT authorization, access tokens, and access control lists:
* **Access Tokens:** Every process runs with a security context containing:
  * User Security Identifier (SID)
  * Group SIDs (e.g., `Administrators`, `Users`, `Backup Operators`, `Guests`)
  * System Privileges (e.g., `SeBackupPrivilege`)
* **DACLs (Discretionary Access Control Lists):** Every securable file or resource has an ordered list of Access Control Entries (ACEs).
* **ACE Evaluation Algorithm (Deny-Before-Allow):**
  1. **Owner Authority:** The file owner has implicit full control.
  2. **Explicit Deny Precedence:** If any matching `DENY` ACE intersects a requested right, access is rejected immediately (even if another group allows it).
  3. **Allow Accumulation:** Matching `ALLOW` ACEs accumulate until all requested rights are satisfied.
  4. **Implicit Deny:** If any requested permission is left ungranted, access is denied by default.
* **Privilege Bypass:** Special tokens with system privileges (like `SeBackupPrivilege`) override normal DACL checks to read protected system files.

---

### 2. macOS Layered Security Model (`macos_acl.c`)
Simulates macOS's 3-tier defence-in-depth security stack:
* **Layer 3 — App Sandbox / TCC Entitlements (Checked First):** Mandatory controls verify whether the application has permission to touch protected privacy categories (e.g., Camera, Documents) before inspecting any file permissions.
* **Layer 2 — NFSv4-Style ACLs (Checked Second):** Evaluates fine-grained allow and deny entries. If no ACE matches, execution falls through to standard Unix permissions.
* **Layer 1 — POSIX Permission Bits (Checked Last):** The classic Unix `rwx` bits for Owner, Group, and Other, plus superuser (`root` / UID 0) bypass.

---

## Architectural Comparison

| Dimension | Windows Security Architecture | macOS Security Architecture |
| :--- | :--- | :--- |
| **Primary Authorization Model** | Pure Access Control Lists (DACLs) | Layered Hybrid (Sandbox $\rightarrow$ ACL $\rightarrow$ POSIX) |
| **Process Identity** | **Access Token** (User SID + Group SIDs + Privileges) | **Process Credentials** (UID + GIDs) + Code Signing Entitlements |
| **Base Permission Unit** | Discretionary Access Control List (DACL) | POSIX mode bits (`rwxrwxrwx` for Owner, Group, Other) |
| **Fine-Grained Permissions** | Explicit `ALLOW` and `DENY` Access Control Entries (ACEs) | NFSv4-style extended ACL entries layered on top of POSIX |
| **Evaluation Algorithm** | Single-pass ordered walk over DACL: explicit DENY stops immediately; ALLOWs accumulate; unmatched rights trigger implicit deny | **3-Tier Short-Circuit**: <br>1. Sandbox Entitlement Check<br>2. ACL Walk (if present)<br>3. POSIX Bit Check |
| **Owner Authority** | Object owner gets implicit `FULL_CONTROL` (can always modify permissions) | Owner rights are governed by POSIX owner bits (`0700`, `0600`, etc.) |
| **Privileged Access** | Granular system privileges (`SeBackupPrivilege`, `SeDebugPrivilege`, etc.) | Superuser (`root`, UID 0) POSIX bypass + TCC system policy |
| **Hardware & Privacy Controls** | Windows Service Isolation & Capabilities (UWP/AppContainer) | TCC (Transparency, Consent, and Control) & App Sandbox entitlements |

---

## How to Compile & Run

### 1. Compile
Run the following commands in PowerShell or Command Prompt:

```powershell
# Compile Windows Security Simulation
gcc -o windows_acl.exe windows_acl.c -Wall

# Compile macOS Security Simulation
gcc -o macos_acl.exe macos_acl.c -Wall
```

---

### 2. Run

#### Windows Security Simulation:
```powershell
.\windows_acl.exe
```
* Select `1` for the preset demo (8 scenarios showing owner access, group permissions, explicit deny, and backup privilege bypass).
* Select `2` for interactive mode (inspect tokens and create custom ACEs).

#### macOS Security Simulation:
```powershell
.\macos_acl.exe
```
* Select `1` for the preset demo (9 scenarios showing Sandbox $\rightarrow$ ACL $\rightarrow$ POSIX evaluation).
* Select `2` for interactive mode (change `chmod` octal modes and test permissions).

---

## Preset Demonstration Scenarios

### Windows Scenarios (`windows_acl.exe`)

| # | Scenario | Request | Result | Principle Demonstrated |
|---|:---|:---|:---:|:---|
| 1 | Alice reads `report.docx` | `READ` | **GRANTED** | **Owner Authority**: File owner has implicit full control. |
| 2 | Bob (member of `Users`) reads `report.docx` | `READ` | **GRANTED** | **Group Allow**: ACE grants `READ` to the `Users` group. |
| 3 | Bob writes `report.docx` | `WRITE` | **DENIED** | **Implicit Deny**: No ACE grants write access to normal users. |
| 4 | Charlie (member of `Guests`) reads `report.docx` | `READ` | **DENIED** | **Explicit Deny**: ACE #1 explicitly denies `Guests`, overriding group allow. |
| 5 | Dave (`Users` + `Backup Ops`) writes `project.xlsx` | `WRITE` | **DENIED** | **Deny Precedence**: `Backup Ops` deny ACE appears before `Users` allow ACE. |
| 6 | Dave reads `project.xlsx` | `READ` | **GRANTED** | **Targeted Deny**: Deny entry only restricts `WRITE`/`DELETE`; `READ` remains allowed. |
| 7 | Bob reads `boot.ini` | `READ` | **DENIED** | **Implicit Deny**: DACL only permits `Administrators`. |
| 8 | Dave reads `boot.ini` | `READ` | **GRANTED** | **Privilege Bypass**: Token carries `SeBackupPrivilege`, overriding the DACL. |

### macOS Scenarios (`macos_acl.exe`)

| # | Scenario | Request | Result | Layer Determining Outcome |
|---|:---|:---|:---:|:---|
| 1 | Alice reads `secrets.txt` | `READ` | **GRANTED** | **Layer 1 (POSIX)**: Sandbox passes; no ACL; POSIX owner bit allows `r`. |
| 2 | Bob reads `secrets.txt` | `READ` | **DENIED** | **Layer 1 (POSIX)**: Sandbox passes; no ACL; POSIX mode `0600` denies other users. |
| 3 | Charlie reads `secrets.txt` | `READ` | **DENIED** | **Layer 3 (Sandbox)**: Process lacks `com.apple.files.documents`; blocked immediately before checking POSIX. |
| 4 | Bob writes `main.c` | `WRITE` | **GRANTED** | **Layer 2 (ACL)**: Sandbox passes; ACL grants `developers` write access. |
| 5 | Alice reads `main.c` | `READ` | **GRANTED** | **Layer 1 (POSIX)**: Sandbox passes; ACL does not match; falls through to POSIX 'other' read bit. |
| 6 | Charlie writes `main.c` | `WRITE` | **DENIED** | **Layer 2 (ACL)**: Sandbox passes; explicit ACL deny for `guest` matches first. |
| 7 | Alice reads `/etc/sudoers` | `READ` | **GRANTED** | **Layer 2 (ACL)**: ACL explicitly allows `admin` group read access. |
| 8 | FaceTime accesses `/dev/camera0` | `READ` | **GRANTED** | **Layer 3 (Sandbox)**: Process has `com.apple.security.device.camera` entitlement; passes to POSIX. |
| 9 | Untrusted app accesses `/dev/camera0` | `READ` | **DENIED** | **Layer 3 (Sandbox)**: Lacks camera entitlement; blocked despite permissive (`0777`) POSIX bits. |

---

## Files in this Repository

| File | Purpose |
| :--- | :--- |
| `windows_acl.c` | Windows security simulator (Access Tokens, DACLs, ACE evaluation) |
| `macos_acl.c` | macOS security simulator (Sandbox Entitlements, ACLs, POSIX bits) |
| `README.md` | Complete architecture and comparison documentation |
