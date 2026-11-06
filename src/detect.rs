use crate::model::{Assessment, Entry, Evidence, PathState, Status};

pub fn assess(entry: Entry, probe: impl Fn(&str) -> PathState) -> Assessment {
    let mut result = Assessment {
        id: entry.location.id(),
        entry,
        status: Status::Review,
        reasons: vec![],
        evidence: vec![],
    };
    let tree = &result.entry.tree;
    for flag in ["SystemComponent", "WindowsInstaller"] {
        if tree.nonzero(flag) {
            result.status = Status::Protected;
            result
                .reasons
                .push(format!("{flag}：系统组件或 MSI 注册，不自动清理"));
            return result;
        }
    }
    for field in ["ParentKeyName", "ReleaseType"] {
        if tree.value(field).is_some() {
            result.status = Status::Protected;
            result
                .reasons
                .push("更新、补丁或子组件注册，不自动清理".into());
            return result;
        }
    }
    let mut no_remove = tree.nonzero("NoRemove");
    let mut malformed = false;
    for field in [
        "InstallLocation",
        "UninstallString",
        "QuietUninstallString",
        "DisplayIcon",
    ] {
        let source = match tree.string(field) {
            Ok(Some(source)) if !source.is_empty() => source,
            Ok(_) => continue,
            Err(_) => {
                malformed = true;
                result.reasons.push(format!("{field} 类型或编码异常"));
                continue;
            }
        };
        // MSI 即使没有 WindowsInstaller 标志也不能按普通 EXE 的存在性判断。
        if field.contains("UninstallString") && source.to_ascii_lowercase().contains("msiexec") {
            result.status = Status::Protected;
            result
                .reasons
                .push("MSI 卸载命令，需使用 Windows Installer 修复/卸载".into());
            return result;
        }
        let path = match field {
            "InstallLocation" => location_path(&source),
            "DisplayIcon" => icon_path(&source),
            _ => executable_path(&source),
        };
        let state = path.as_deref().map(&probe).unwrap_or(PathState::Unknown);
        result.evidence.push(Evidence {
            field: field.into(),
            source,
            state,
        });
    }
    if result
        .evidence
        .iter()
        .any(|e| e.state == PathState::Present)
    {
        result.status = Status::Keep;
        result
            .reasons
            .push("安装目录、图标或卸载程序仍存在，保留该记录".into());
        return result;
    }
    // 含子键的条目可能参与安装器维护，不能批量删除。
    if !tree.children.is_empty() {
        no_remove = true;
        result.reasons.push("含安装器子键，需人工核实".into());
    }
    if no_remove {
        result
            .reasons
            .push("禁止卸载标志或安装器维护信息，需人工核实".into());
    }
    let missing_location = result
        .evidence
        .iter()
        .any(|e| e.field == "InstallLocation" && e.state == PathState::Missing);
    let missing_target = result
        .evidence
        .iter()
        .any(|e| e.field != "InstallLocation" && e.state == PathState::Missing);
    let unknown = malformed
        || result
            .evidence
            .iter()
            .any(|e| e.state == PathState::Unknown);
    if missing_location && missing_target && !unknown && !no_remove {
        result.status = Status::Candidate;
        result
            .reasons
            .push("安装目录及至少一个卸载程序/图标均不存在，且没有相反证据".into());
    } else {
        result
            .reasons
            .push("证据不足；仅可确认软件已卸载后，按精确 ID 手动清理".into());
    }
    result
}

fn unquote(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.starts_with('"') {
        value.strip_prefix('"')?.strip_suffix('"')
    } else if value.contains('"') {
        None
    } else {
        Some(value)
    }
}

fn absolute_local(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !path.contains(['\0', '"', '*', '?', '/', '\r', '\n'])
        && !path[2..].contains(':')
        && !path
            .split('\\')
            .any(|part| part == "." || part == ".." || part.ends_with([' ', '.']))
}

pub fn expand_path(value: &str) -> Option<String> {
    let mut out = String::new();
    let mut remaining = value;
    while let Some(start) = remaining.find('%') {
        out.push_str(&remaining[..start]);
        let after = &remaining[start + 1..];
        let end = after.find('%')?;
        if end == 0 {
            return None;
        }
        out.push_str(&std::env::var(&after[..end]).ok()?);
        remaining = &after[end + 1..];
    }
    out.push_str(remaining);
    if out.contains('%') {
        return None;
    }
    Some(out)
}

pub fn location_path(value: &str) -> Option<String> {
    let expanded = expand_path(value)?;
    let path = unquote(&expanded)?;
    absolute_local(path).then(|| path.to_string())
}

pub fn icon_path(value: &str) -> Option<String> {
    let expanded = expand_path(value)?;
    let path = if let Some((path, index)) = expanded.rsplit_once(',') {
        if index.trim().parse::<i32>().is_ok() {
            path
        } else {
            &expanded
        }
    } else {
        &expanded
    };
    let path = unquote(path)?;
    absolute_local(path).then(|| path.to_string())
}

pub fn executable_path(value: &str) -> Option<String> {
    let expanded = expand_path(value)?;
    let command = expanded.trim();
    let path = if let Some(after) = command.strip_prefix('"') {
        let end = after.find('"')?;
        if after[end + 1..]
            .chars()
            .next()
            .is_some_and(|c| !c.is_whitespace())
        {
            return None;
        }
        &after[..end]
    } else {
        // 无引号的含空格路径在 Windows 上有多种解释，保守地拒绝猜测。
        let end = command.find(char::is_whitespace).unwrap_or(command.len());
        let rest = command[end..].trim_start();
        if !rest.is_empty() && !rest.starts_with(['/', '-']) {
            return None;
        }
        &command[..end]
    };
    let lower = path.to_ascii_lowercase();
    if !lower.ends_with(".exe") || !absolute_local(path) {
        return None;
    }
    let name = lower.rsplit('\\').next()?;
    if [
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "wscript.exe",
        "cscript.exe",
        "msiexec.exe",
        "explorer.exe",
        "winget.exe",
    ]
    .contains(&name)
    {
        return None;
    }
    Some(path.to_string())
}

#[cfg(windows)]
pub fn probe(path: &str) -> PathState {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    if !absolute_local(path) {
        return PathState::Unknown;
    }
    let root = &path[..3];
    let wide: Vec<_> = root.encode_utf16().chain(Some(0)).collect();
    // DRIVE_FIXED=3；网络、移动盘或离线卷不能提供可靠的缺失证据。
    if unsafe { GetDriveTypeW(wide.as_ptr()) } != 3 || std::fs::metadata(root).is_err() {
        return PathState::Unknown;
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => PathState::Present,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // 沿途的 junction/symlink/offline cloud placeholder 可能指向暂不可用的位置。
            let mut ancestor = std::path::Path::new(path).parent();
            while let Some(parent) = ancestor {
                match std::fs::symlink_metadata(parent) {
                    Ok(meta) if meta.file_attributes() & (0x400 | 0x1000) != 0 => {
                        return PathState::Unknown;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return PathState::Unknown,
                }
                ancestor = parent.parent();
            }
            PathState::Missing
        }
        Err(_) => PathState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hive, Location, RawValue, Tree, View};

    pub fn string(value: &str) -> RawValue {
        RawValue {
            kind: 1,
            bytes: value
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    pub fn entry() -> Entry {
        Entry {
            location: Location {
                hive: Hive::HKCU,
                view: View::Registry64,
                key: "test".into(),
            },
            name: "测试程序".into(),
            version: "1.0".into(),
            tree: Tree {
                values: [
                    ("InstallLocation".into(), string(r"C:\Removed\App")),
                    (
                        "UninstallString".into(),
                        string(r#""C:\Removed\App\uninstall.exe" /S"#),
                    ),
                ]
                .into(),
                children: Default::default(),
            },
        }
    }
    #[test]
    fn requires_multiple_missing_paths() {
        assert_eq!(
            assess(entry(), |_| PathState::Missing).status,
            Status::Candidate
        );
        let mut e = entry();
        e.tree.values.remove("InstallLocation");
        assert_eq!(assess(e, |_| PathState::Missing).status, Status::Review);
    }
    #[test]
    fn existing_or_unreadable_evidence_prevents_auto_cleanup() {
        assert_eq!(assess(entry(), |_| PathState::Present).status, Status::Keep);
        assert_eq!(
            assess(entry(), |_| PathState::Unknown).status,
            Status::Review
        );
        assert_eq!(
            assess(entry(), |p| if p.ends_with(".exe") {
                PathState::Missing
            } else {
                PathState::Present
            })
            .status,
            Status::Keep
        );
    }
    #[test]
    fn protects_msi_system_updates_and_disabled_removal() {
        for flag in ["SystemComponent", "WindowsInstaller"] {
            let mut e = entry();
            e.tree.values.insert(
                flag.into(),
                RawValue {
                    kind: 4,
                    bytes: 1u32.to_le_bytes().into(),
                },
            );
            assert_eq!(assess(e, |_| PathState::Missing).status, Status::Protected);
        }
        for field in ["ParentKeyName", "ReleaseType"] {
            let mut e = entry();
            e.tree.values.insert(field.into(), string("Update"));
            assert_eq!(assess(e, |_| PathState::Missing).status, Status::Protected);
        }
        let mut e = entry();
        e.tree.values.insert(
            "NoRemove".into(),
            RawValue {
                kind: 4,
                bytes: 1u32.to_le_bytes().into(),
            },
        );
        assert_eq!(assess(e, |_| PathState::Missing).status, Status::Review);
        let mut e = entry();
        e.tree
            .values
            .insert("UninstallString".into(), string("MsiExec.exe /X{test}"));
        assert_eq!(assess(e, |_| PathState::Missing).status, Status::Protected);
    }
    #[test]
    fn complex_paths_are_never_guessed() {
        for command in [
            r"C:\Program.exe Files\App\uninstall.exe /S",
            r"C:\Program Files\App\uninstall.exe /S",
            "uninstall.exe /S",
            r"C:\Windows\System32\cmd.exe /c something",
            r"\\server\app\uninstall.exe",
            r#""C:\App\uninstall.exe"garbage"#,
        ] {
            assert!(executable_path(command).is_none(), "{command}");
        }
        assert_eq!(
            executable_path(r#""C:\Program Files\App\uninstall.exe" /S"#).as_deref(),
            Some(r"C:\Program Files\App\uninstall.exe")
        );
        assert_eq!(
            icon_path(r#""C:\My App\app.exe",-2"#).as_deref(),
            Some(r"C:\My App\app.exe")
        );
        for path in [
            r"C:\Apps\..\Windows",
            r"Z:\",
            r"C:\Apps\x.",
            r"%CLEAN_SOFTWARE_TEST_UNDEFINED%\foo",
            r"C:relative",
            r"C:\foo:bar",
        ] {
            assert!(location_path(path).is_none(), "{path}");
        }
    }
    #[test]
    fn malformed_value_is_not_absent() {
        let mut e = entry();
        e.tree.values.insert(
            "QuietUninstallString".into(),
            RawValue {
                kind: 3,
                bytes: vec![],
            },
        );
        assert_eq!(assess(e, |_| PathState::Missing).status, Status::Review);
    }
}
