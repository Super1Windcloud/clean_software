# clean_software

**English** | [简体中文](README.zh-CN.md)

[![crates.io](https://img.shields.io/crates/v/clean_software.svg)](https://crates.io/crates/clean_software)

A Windows CLI for removing stale uninstall registry entries from **Settings → Apps → Installed apps** after the software has been removed. Written in Rust for Windows 10/11. Building requires Rust 1.88+.

## Installation

Published on [crates.io](https://crates.io/crates/clean_software). On Windows with Rust 1.88+ installed, install or update to the latest release:

```powershell
cargo install clean_software --locked
clean_software --version
```

Make sure Cargo's installation `bin` directory is on your `PATH` (by default, `%USERPROFILE%\.cargo\bin`).

### Build from source

From the repository root:

```powershell
cargo build --release --locked
.\target\release\clean_software.exe --version
```

If building from source, replace `clean_software` in the examples below with `.\target\release\clean_software.exe`.

## Usage

Run in PowerShell. Cleaning or restoring system-wide (HKLM) entries usually requires an administrator terminal.

```powershell
# Scan by default; no registry changes
clean_software

# Preview entries eligible for automatic cleanup
clean_software clean --dry-run

# Clean candidates with automatic backup; omit --yes for a batch confirmation
clean_software clean --yes
```

Only the selected **Uninstall registry entries** are deleted. The tool does not uninstall software, execute commands stored in the registry, delete application files, or scan unrelated registry locations. Close and reopen Windows Settings after cleanup.

## Scanning and targeted cleanup

```powershell
# Show all entries and evidence, including retained and protected entries
clean_software scan --all

# Filter by application name substring, or export JSON with exact IDs, evidence, and warnings
clean_software scan --name 'Application name'
clean_software scan --all --json

# Copy the exact ID from scan output; --id can be repeated
clean_software clean --id 'HKCU/64/Registry subkey name' --dry-run

# Clean an entry requiring review after confirming the software has been removed
clean_software clean --id 'HKCU/64/Registry subkey name' --include-review --yes
```

| Classification | Criteria | Cleanup |
| --- | --- | --- |
| Candidate | The installation directory and at least one uninstaller/icon are missing on an online local fixed disk, with no existing or unknown paths among the other supplied evidence | `clean` or `clean --yes` |
| Review | Insufficient evidence, unresolved paths, a removal restriction, installer subkeys, etc. | Requires an exact `--id` and `--include-review` |
| Keep | Any installation directory, uninstaller, or icon still exists | Cleanup refused |
| Protected | MSI, system components, patches, updates, or child components | Cleanup refused |

**Detection is heuristic and cannot prove that an application has been uninstalled.** Review `clean --dry-run` first; moving an installation directory can also leave an invalid entry. A disabled uninstall button may reflect a valid `NoRemove` setting and does not establish that the entry is stale. For stale MSI entries, use the vendor's repair tools or Windows Installer first. This tool does not maintain the MSI product database or handle Microsoft Store / Appx package registration.

Unresolved environment variables, unquoted executable paths containing spaces, generic script launchers, UNC/network paths, removable or offline drives, permission errors, and missing paths traversing junctions or symlinks do not count as reliable evidence of absence. Existing installation directories are retained even when empty, to avoid removing entries that may still be in use.

## Backup and restore

Before cleanup, the tool saves all selected entries to JSON, preserving raw value types, bytes, and subkeys, then calls `sync_all`. Backups use unique filenames under `%LOCALAPPDATA%\clean_software\backups`; the actual path is printed. Use `--backup 'D:\Backups\apps.json'` to specify a file. Existing files are never overwritten. The backup includes every selected entry, including entries later skipped because of permission errors or changes. Registry ACLs and last-write timestamps are not preserved.

```powershell
clean_software restore 'C:\Path\backup.json' --dry-run
clean_software restore 'C:\Path\backup.json' --yes

# After partial cleanup, skip existing entries and restore missing ones without overwriting
clean_software restore 'C:\Path\backup.json' --skip-existing --yes
```

Each deletion uses a Windows registry transaction and rechecks the original data and path evidence before deleting; changed entries are skipped. Restore uses one transaction for the entire batch and, by default, cancels the batch if any entry already exists. Use `--skip-existing` to explicitly skip existing entries. If transactions are unavailable, the operation fails without falling back to nontransactional writes. Backups are limited to 32 MiB. Restore targets are restricted to HKCU/HKLM uninstall subkeys; symbolic links and invalid subkey paths are rejected. Restore on the original machine under the original user account.

## Scope and exit codes

- HKLM: the 64-bit and 32-bit views of `Software\Microsoft\Windows\CurrentVersion\Uninstall`.
- HKCU: the shared `Software\Microsoft\Windows\CurrentVersion\Uninstall` location (labeled `HKCU/64` on 64-bit systems), plus `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall` explicitly written by some installers (labeled `HKCU/32`). This avoids enumerating the shared view twice. On 32-bit systems, only native locations are scanned.
- Only the current user's hive is scanned; other users' hives are not loaded. The tool does not use `Win32_Product`, which can trigger MSI repairs.
- Exit code `0`: completed, no candidates, or user cancellation. `1`: an error or partial cleanup failure. `2`: invalid command arguments. Scan permission errors are added to the warnings list while other locations continue to be scanned. Always inspect `warnings` in JSON output; a scan with warnings must not be treated as complete.
- Noninteractive cleanup and restore require `--yes`. Permission errors are reported without automatic elevation.

## Validation

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Tests create temporary HKCU uninstall entries with unique `CleanSoftware_Test_*` / `CleanSoftware_CliTest_*` names, remove only those entries, and clean up test backups in the system temporary directory. Real application entries are not cleaned. Coverage includes 32-bit/64-bit locations, round trips for raw value types and nested subkeys, changes after scanning, protected-entry refusal, restore-conflict rollback, and CLI preview, confirmation, and backup-failure paths.

References: [Uninstall registry fields](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key), [NoRemove](https://learn.microsoft.com/en-us/windows/win32/msi/arpnoremove), and [registry views](https://learn.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry).
