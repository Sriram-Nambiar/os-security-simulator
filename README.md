# Windows Security Simulator: Access Tokens, DACLs & Permission Inheritance

An educational Operating System Security Simulator in C that models how **Microsoft Windows NT** manages authorization, process credentials, and **NTFS-style Permission Inheritance (Folders -> Files)**.

---

## What It Simulates

This project simulates the core mechanisms Windows uses to determine whether a process is allowed to access securable resources:

### 1. Access Tokens
Every process executes within the security context of an **Access Token**:
* **User SID:** Identifies the user account that owns the process.
* **Group SIDs:** List of groups the user belongs to (e.g., `Administrators`, `Users`, `Backup Operators`, `Guests`).
* **Privileges:** Special system-wide capabilities that can bypass standard security checks (e.g., `SeBackupPrivilege`).

---

### 2. Security Descriptors & DACLs
Every protected object has a **Security Descriptor** containing:
* **Owner SID:** The user who owns the resource.
* **DACL (Discretionary Access Control List):** An ordered array of **Access Control Entries (ACEs)**.
* **Inheritance Metadata:** Specifies whether a rule is **`[EXPLICIT]`** (defined directly on the object) or **`[INHERITED]`** (propagated from a parent folder).

---

### 3. Permission Inheritance (Folders -> Files)
In Windows NTFS, child files and subdirectories inherit permissions from their parent containers:
* **Inheritance Propagation:** Child resources automatically receive copies of their parent folder's DACL entries.
* **Breaking Inheritance:** Administrators can toggle inheritance on or off (blocking inherited permissions).
* **Canonical Windows Evaluation Precedence:**
  1. **Owner Check:** Implicit full control.
  2. **Explicit DENY ACEs:** If any explicit deny matches requested rights $\rightarrow$ **DENY immediately**.
  3. **Explicit ALLOW ACEs:** Accumulate rights. If all requested rights are satisfied $\rightarrow$ **GRANT immediately**! *(This enables an Explicit Allow on a file to override an Inherited Deny from a parent folder!)*
  4. **Inherited DENY ACEs:** Check parent folder denials for remaining rights.
  5. **Inherited ALLOW ACEs:** Accumulate parent folder allowances.
  6. **Implicit Deny:** If any requested right remains ungranted $\rightarrow$ **DENY by default**.

---

### 4. Privilege Bypass
Special tokens with system privileges (like `SeBackupPrivilege`) override normal DACL checks to read protected system files.

---

## How to Compile & Run

### 1. Compile
```powershell
gcc -o windows_acl.exe windows_acl.c -Wall
```

### 2. Run
```powershell
.\windows_acl.exe
```
* **`1` (Preset Demo):** Automatically walks through 8 test cases demonstrating inheritance, explicit allow vs. inherited deny, explicit deny vs. inherited allow, and privilege overrides.
* **`2` (Interactive Mode):** Inspect the folder/file tree, view inherited vs. explicit ACEs, toggle inheritance on/off, add custom ACEs, and test permissions.

---

## Preset Demonstration Scenarios

| # | Scenario | Resource | Requested | Result | Principle Demonstrated |
|---|:---|:---|:---:|:---:|:---|
| 1 | Alice reads `specs.docx` | `C:\Projects\specs.docx` | `READ` | **GRANTED** | **Owner Authority:** Alice owns the file; implicit full control. |
| 2 | Bob reads `specs.docx` | `C:\Projects\specs.docx` | `READ` | **GRANTED** | **Inherited Allowance:** Inherited from folder `C:\Projects`. |
| 3 | Charlie reads `specs.docx` | `C:\Projects\specs.docx` | `READ` | **DENIED** | **Inherited Denial:** Inherited `DENY Guests` from folder `C:\Projects`. |
| 4 | Charlie reads `public_notes.txt` | `C:\Projects\public_notes.txt` | `READ` | **GRANTED** | **Explicit Allow Overrides Inherited Deny:** An explicit allow on the child file beats parent folder's deny! |
| 5 | Bob reads `secret_budget.xlsx` | `C:\Projects\secret_budget.xlsx` | `READ` | **DENIED** | **Explicit Deny Overrides Inherited Allow:** An explicit deny on the child file blocks access despite parent folder allow! |
| 6 | Bob writes `specs.docx` | `C:\Projects\specs.docx` | `WRITE` | **DENIED** | **Implicit Deny:** Folder only grants READ; write is never granted. |
| 7 | Bob reads `boot.ini` | `C:\System\boot.ini` | `READ` | **DENIED** | **Administrative Isolation:** DACL only permits Administrators. |
| 8 | Dave reads `boot.ini` | `C:\System\boot.ini` | `READ` | **GRANTED** | **Privilege Override:** Token carries `SeBackupPrivilege`, bypassing the DACL. |

---

## Repository Files

| File | Purpose |
| :--- | :--- |
| `windows_acl.c` | Windows security simulator with Folder $\rightarrow$ File inheritance |
| `README.md` | Architecture and inheritance documentation |
| `Project_Report.pdf` | Comprehensive academic project report |
