# osep_enum

A Beacon Object File (BOF) port of `OSEP_enum.ps1` — a comprehensive local host enumeration sweep designed for post-exploitation. Part of the [SAL-BOF](https://github.com/0xGunrunner/SAL-BOF) collection.

Runs eight enumeration sections in a single BOF execution with no child process spawns and no PowerShell.

## What it does

| # | Section | Details |
|---|---------|---------|
| 1 | **Network shares** | Enumerates local shares via `NetShareEnum` — name, type, remark |
| 2 | **Interesting files** | Recursive search under `C:\Users` (depth 6) for `.xml .txt .pdf .xls .xlsx .doc .docx .log .exe` and exact matches `id_rsa`, `authorized_keys` |
| 3 | **Directory listings** | One-level subdirectory listing of `C:\`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData` |
| 4 | **Flag files** | Searches `C:\` (root only) and `C:\Users` (depth 6) for `local.txt` and `proof.txt` |
| 5 | **Listening TCP ports** | `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_LISTENER` — prints address, port, PID, and resolved process name |
| 6 | **IIS wwwroot write check** | Creates and deletes a test file in `C:\inetpub\wwwroot` — flags writable root as a `SeImpersonate → SYSTEM` path via ASPX shell |
| 7 | **Sticky Notes + PS history** | Enumerates all user profiles under `C:\Users`, locates `ConsoleHost_history.txt` (PSReadLine) and the Sticky Notes `LocalState` SQLite store for each user |
| 8 | **Installed services** | Enumerates `HKLM\SYSTEM\CurrentControlSet\Services` via registry — no SCM handle required |

## Usage

```
osep-enum
```

No arguments. Runs all eight sections sequentially and prints results inline.

### Example output

```
==========================================
          OSEP Enumeration BOF
==========================================

========================================
[1] NETWORK SHARES
========================================
  ADMIN$               Type: 2147483648  Remark: Remote Admin
  C$                   Type: 2147483648  Remark: Default share
  IPC$                 Type: 2147483651  Remark: Remote IPC

========================================
[2] INTERESTING FILES IN C:\Users
========================================
  C:\Users\bob\Documents\creds.txt
  C:\Users\bob\.ssh\id_rsa

========================================
[5] LISTENING TCP PORTS
========================================
  Address:Port           PID       Process
  ------------           ---       -------
  0.0.0.0:445            4         System
  0.0.0.0:3389           1234      svchost.exe
  127.0.0.1:8080         4321      tomcat9.exe

========================================
[6] IIS WWWROOT WRITE CHECK
========================================
  [+] WRITE ACCESS CONFIRMED to C:\inetpub\wwwroot
      Consider dropping an ASPX shell for SeImpersonate -> SYSTEM.

========================================
[7] STICKY NOTES + POWERSHELL HISTORY
========================================
  [PSHistory]    C:\Users\bob\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
  [StickyNotes]  C:\Users\bob\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite

[*] Enumeration complete.
```

## Building

Requires `mingw-w64` cross-compiler on Linux/macOS.

```bash
# x64
x86_64-w64-mingw32-gcc -c osep_enum.c -masm=intel -o _bin/osep_enum.x64.o

# x86
i686-w64-mingw32-gcc -c osep_enum.c -masm=intel -o _bin/osep_enum.x86.o
```

Place the compiled `.o` files in your `_bin/` directory alongside the rest of SAL-BOF.

### Dependencies

- `beacon.h` — standard Cobalt Strike / AdaptixC2 BOF header (not included, place in the same directory as `osep_enum.c`)
- `KERNEL32` — file search, process query, heap allocation
- `IPHLPAPI` — `GetExtendedTcpTable` for TCP port enumeration
- `NETAPI32` — `NetShareEnum` for share enumeration
- `ADVAPI32` — registry access for service enumeration
- `MSVCRT` — wide string helpers

No external libraries beyond what is already present on any Windows installation.

## Integration — AdaptixC2 (SAL-BOF.axs)

`osep-enum` is registered as a top-level command in the AXS extension file:

```javascript
var cmd_osep_enum = ax.create_command(
    "osep-enum",
    "Local host enumeration: shares, interesting files, listening ports, IIS write check, sticky notes, PS history, services",
    "osep-enum"
);
cmd_osep_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/osep_enum." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: osep-enum");
});
```

## Technical notes

**No PowerShell, no child processes**
The original `OSEP_enum.ps1` is a PowerShell script — visible in process telemetry, subject to AMSI, and logged by Script Block Logging and Transcription. This BOF runs entirely in the beacon process with no spawned processes and no PowerShell engine invocation.

**Interesting file search depth**
Section 2 recurses to depth 6 under `C:\Users`. On a heavily populated profile this can produce significant output and take a few seconds. If the beacon has a short sleep this is unlikely to cause a timeout, but worth noting on hosts with very large user directories.

**IIS write check cleanup**
The write check (Section 6) creates `bof_write_test.tmp` in `C:\inetpub\wwwroot` and immediately deletes it. If the BOF crashes between the create and delete calls the temp file will remain — remove it manually if needed.

**Service enumeration via registry**
Section 8 reads directly from `HKLM\SYSTEM\CurrentControlSet\Services` rather than opening an SCM handle. This avoids the `SC_MANAGER_ENUMERATE_SERVICE` access right requirement and produces output even in restricted token contexts, at the cost of listing driver keys alongside Win32 services.

**Sticky Notes path**
The Sticky Notes `LocalState` folder is enumerated by package family name (`Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe`). This path is stable across Windows 10/11 versions. The SQLite file (`plum.sqlite`) can be copied and opened offline with any SQLite browser to read note content.

## Related

- `privcheck modsvc` — checks per-service DACL for modifiable services
- `privcheck scmcheck` — checks SCM-level permissions
- `privcheck all` — runs all SAL-BOF privilege escalation checks sequentially

## Disclaimer

This tool is provided for authorized penetration testing and security research only. You are responsible for ensuring you have explicit written permission before running this or any offensive security tool against any system. The author accepts no liability for misuse or damage caused by this software.

## Author

[0xGunrunner](https://github.com/0xGunrunner)
