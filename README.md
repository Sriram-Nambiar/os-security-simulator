# OS Simulator

An educational Operating System Simulator that demonstrates how modern operating systems handle **process scheduling** and **access control security** under the hood.

---

## What It Simulates

This project simulates three major core OS subsystems across **Microsoft Windows** and **Apple macOS**:

### 1. CPU Process Scheduling (`winsim.c`)
Simulates the core algorithms used by operating system schedulers:
* **Preemptive Priority Scheduling:** The CPU always executes the highest-priority ready process; any arriving higher-priority task preempts the running process immediately.
* **Time Quantum / Round-Robin:** Each process receives a fixed time slice before yielding the CPU.
* **Dynamic I/O Priority Boosting:** When an interactive process finishes waiting on I/O (disk, keyboard, network), its priority is temporarily boosted so it responds quickly to user input, then gradually decays over time.

---

### 2. Windows Security Model (`windows_acl.c`)
Simulates Windows NT authorization, access tokens, and access control lists:
* **Access Tokens:** Every process runs with a security token containing the User SID, Group SIDs (e.g., `Administrators`, `Backup Operators`), and Privileges.
* **DACLs (Discretionary Access Control Lists):** Every securable file or resource has an ordered list of Access Control Entries (ACEs).
* **ACE Evaluation Algorithm (Deny-Before-Allow):**
  1. **Owner Check:** The file owner has implicit full control.
  2. **Explicit Deny Precedence:** If any matching `DENY` ACE covers a requested right, access is rejected immediately (even if another group allows it).
  3. **Allow Accumulation:** Matching `ALLOW` ACEs accumulate until all requested rights are satisfied.
  4. **Implicit Deny:** If any requested permission is left ungranted, access is denied by default.
* **Privilege Bypass:** Special tokens with system privileges (like `SeBackupPrivilege`) override normal DACL checks to read protected system files.

---

### 3. macOS Security Model (`macos_acl.c`)
Simulates macOS's layered defence-in-depth security stack:
* **Layer 3 — App Sandbox / TCC Entitlements (Checked First):** Mandatory controls verify whether the application has permission to touch protected privacy categories (e.g., Camera, Documents) before looking at any file permissions.
* **Layer 2 — NFSv4-Style ACLs (Checked Second):** Evaluates fine-grained allow and deny entries. If no ACE matches, execution falls through to standard Unix permissions.
* **Layer 1 — POSIX Permission Bits (Checked Last):** The classic Unix `rwx` bits for Owner, Group, and Other, plus superuser (`root` / UID 0) bypass.

---

## How to Compile & Run

### 1. Compile
Run the following commands in PowerShell or Command Prompt:

```powershell
# Compile the CPU Scheduler
gcc -o winsim.exe winsim.c -Wall

# Compile Windows Security Model
gcc -o windows_acl.exe windows_acl.c -Wall

# Compile macOS Security Model
gcc -o macos_acl.exe macos_acl.c -Wall
```

---

### 2. Run

#### Windows CPU Scheduler:
```powershell
.\winsim.exe
```
* Select `1` to run the preset demo showing preemption and I/O boosting.
* Select `2` to enter custom processes.

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

## Files in this Repository

| File | Purpose |
| :--- | :--- |
| `winsim.c` | CPU scheduling simulator (priorities, quantum, dynamic boosting) |
| `windows_acl.c` | Windows security simulator (Access Tokens, DACLs, ACE evaluation) |
| `macos_acl.c` | macOS security simulator (Sandbox Entitlements, ACLs, POSIX bits) |
| `README.md` | Overview and documentation |
