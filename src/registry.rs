use crate::backup::Backup;
use crate::detect;
use crate::model::{
    Assessment, Entry, Hive, Location, RawValue, Status, Tree, UNINSTALL, View, validate_key_name,
};
use anyhow::{Context, Result, bail, ensure};
use std::io;
use winreg::{RegKey, RegValue, enums::*, transaction::Transaction};

pub struct Report {
    pub items: Vec<Assessment>,
    pub warnings: Vec<String>,
}

fn root(hive: &Hive) -> RegKey {
    RegKey::predef(match hive {
        Hive::HKCU => HKEY_CURRENT_USER,
        Hive::HKLM => HKEY_LOCAL_MACHINE,
    })
}

fn os_is_64() -> bool {
    use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut info);
        matches!(info.Anonymous.Anonymous.wProcessorArchitecture, 6 | 9 | 12)
    }
}

fn flags(location: &Location) -> u32 {
    // HKCU\Software 通常共享视图，显式的 Wow6432Node 是单独的物理位置。
    match (&location.hive, location.view) {
        (Hive::HKCU, _) | (_, View::Registry64) => KEY_WOW64_64KEY,
        (_, View::Registry32) => KEY_WOW64_32KEY,
    }
}

fn base(location: &Location) -> &'static str {
    if location.hive == Hive::HKCU && location.view == View::Registry32 && os_is_64() {
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    } else {
        UNINSTALL
    }
}

// 总是以 OPEN_LINK 打开并拒绝链接，避免跟随恶意/异常注册表符号链接。
fn open(
    parent: &RegKey,
    path: &str,
    view_flags: u32,
    tx: Option<&Transaction>,
) -> io::Result<RegKey> {
    match tx {
        Some(tx) => parent.open_subkey_transacted_with_options_flags(
            path,
            tx,
            REG_OPTION_OPEN_LINK,
            KEY_READ | view_flags,
        ),
        None => {
            parent.open_subkey_with_options_flags(path, REG_OPTION_OPEN_LINK, KEY_READ | view_flags)
        }
    }
}

fn snapshot(key: &RegKey, view_flags: u32, tx: Option<&Transaction>, depth: usize) -> Result<Tree> {
    ensure!(depth <= 32, "注册表子树过深，跳过");
    let mut tree = Tree::default();
    for value in key.enum_values() {
        let (name, value) = value?;
        ensure!(!name.contains(['\0', '\u{fffd}']), "异常值名，无法无损备份");
        ensure!(
            value.vtype != REG_LINK && !name.eq_ignore_ascii_case("SymbolicLinkValue"),
            "拒绝注册表符号链接"
        );
        tree.values.insert(
            name,
            RawValue {
                kind: value.vtype as u32,
                bytes: value.bytes,
            },
        );
    }
    for name in key.enum_keys() {
        let name = name?;
        validate_key_name(&name)?;
        let child = open(key, &name, view_flags, tx)?;
        tree.children
            .insert(name, snapshot(&child, view_flags, tx, depth + 1)?);
    }
    Ok(tree)
}

fn read_entry(
    parent: &RegKey,
    location: Location,
    tx: Option<&Transaction>,
) -> Result<Option<Entry>> {
    location.validate()?;
    let key = open(parent, &location.key, flags(&location), tx)?;
    let tree = snapshot(&key, flags(&location), tx, 0)?;
    let Some(name) = tree.string("DisplayName")?.filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    // 版本格式异常不影响保护判定，也不会把它当成路径缺失。
    let version = tree
        .string("DisplayVersion")
        .ok()
        .flatten()
        .unwrap_or_default();
    Ok(Some(Entry {
        location,
        name,
        version,
        tree,
    }))
}

pub fn scan() -> Result<Report> {
    let mut report = Report {
        items: vec![],
        warnings: vec![],
    };
    let views = if os_is_64() {
        vec![View::Registry64, View::Registry32]
    } else {
        vec![View::Registry32]
    };
    for hive in [Hive::HKCU, Hive::HKLM] {
        for &view in &views {
            let location = Location {
                hive: hive.clone(),
                view,
                key: String::new(),
            };
            let parent = match open(&root(&hive), base(&location), flags(&location), None) {
                Ok(parent) => parent,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    report.warnings.push(format!("{:?}/{view:?}: {e}", hive));
                    continue;
                }
            };
            for name in parent.enum_keys() {
                let name = match name {
                    Ok(name) => name,
                    Err(e) => {
                        report
                            .warnings
                            .push(format!("枚举 {:?}/{view:?}: {e}", hive));
                        continue;
                    }
                };
                let location = Location {
                    key: name,
                    ..location.clone()
                };
                match read_entry(&parent, location.clone(), None) {
                    Ok(Some(entry)) => report.items.push(detect::assess(entry, detect::probe)),
                    Ok(None) => {}
                    Err(e) => report.warnings.push(format!("{}: {e:#}", location.id())),
                }
            }
        }
    }
    report
        .items
        .sort_by_cached_key(|a| (a.entry.name.to_lowercase(), a.entry.location.id()));
    Ok(report)
}

pub fn remove(expected: &Assessment, include_review: bool) -> Result<()> {
    let location = &expected.entry.location;
    location.validate()?;
    let tx = Transaction::new().context("无法启动注册表事务，未删除任何记录")?;
    let parent = root(&location.hive).open_subkey_transacted_with_options_flags(
        base(location),
        &tx,
        REG_OPTION_OPEN_LINK,
        KEY_READ | KEY_WRITE | flags(location),
    )?;
    let entry = read_entry(&parent, location.clone(), Some(&tx))?
        .context("记录已消失或无有效 DisplayName")?;
    ensure!(
        entry.tree == expected.entry.tree,
        "记录自扫描后已变化，拒绝删除"
    );
    let current = detect::assess(entry, detect::probe);
    ensure!(
        current.status == Status::Candidate || (include_review && current.status == Status::Review),
        "当前证据已变化或记录受到保护，拒绝删除"
    );
    delete_tree(&parent, &location.key, flags(location), &tx)?;
    drop(parent);
    tx.commit().context("注册表事务提交失败，删除已回滚")?;
    // 确认选定视图中的记录已消失。
    let parent = open(&root(&location.hive), base(location), flags(location), None)?;
    match open(&parent, &location.key, flags(location), None) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("删除后记录仍存在或被安装器重新创建"),
        Err(e) => Err(e.into()),
    }
}

fn delete_tree(parent: &RegKey, name: &str, view_flags: u32, tx: &Transaction) -> Result<()> {
    validate_key_name(name)?;
    let key = open(parent, name, view_flags, Some(tx))?;
    let children: Vec<_> = key.enum_keys().collect::<io::Result<_>>()?;
    for child in children {
        delete_tree(&key, &child, view_flags, tx)?;
    }
    drop(key);
    parent.delete_subkey_transacted_with_flags(name, tx, view_flags)?;
    Ok(())
}

fn reg_type(kind: u32) -> Result<RegType> {
    Ok(match kind {
        0 => REG_NONE,
        1 => REG_SZ,
        2 => REG_EXPAND_SZ,
        3 => REG_BINARY,
        4 => REG_DWORD,
        5 => REG_DWORD_BIG_ENDIAN,
        7 => REG_MULTI_SZ,
        8 => REG_RESOURCE_LIST,
        9 => REG_FULL_RESOURCE_DESCRIPTOR,
        10 => REG_RESOURCE_REQUIREMENTS_LIST,
        11 => REG_QWORD,
        _ => bail!("不支持的注册表值类型: {kind}"),
    })
}

fn write_tree(key: &RegKey, tree: &Tree, view_flags: u32, tx: &Transaction) -> Result<()> {
    for (name, value) in &tree.values {
        key.set_raw_value(
            name,
            &RegValue {
                vtype: reg_type(value.kind)?,
                bytes: value.bytes.clone(),
            },
        )?;
    }
    for (name, tree) in &tree.children {
        let (child, disposition) =
            key.create_subkey_transacted_with_flags(name, tx, KEY_READ | KEY_WRITE | view_flags)?;
        ensure!(
            disposition == REG_CREATED_NEW_KEY,
            "恢复时子键已存在，拒绝覆盖"
        );
        write_tree(&child, tree, view_flags, tx)?;
    }
    Ok(())
}

pub struct RestoreOutcome {
    pub restored: usize,
    pub skipped: usize,
}

pub fn restore(backup: &Backup, skip_existing: bool) -> Result<RestoreOutcome> {
    backup.validate()?;
    let tx = Transaction::new().context("无法启动恢复事务")?;
    let mut outcome = RestoreOutcome {
        restored: 0,
        skipped: 0,
    };
    for item in &backup.items {
        let location = &item.location;
        ensure!(
            os_is_64() || location.view == View::Registry32,
            "32 位系统不能恢复 64 位视图"
        );
        if skip_existing {
            let path = format!("{}\\{}", base(location), location.key);
            match open(&root(&location.hive), &path, flags(location), Some(&tx)) {
                Ok(_) => {
                    outcome.skipped += 1;
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let (parent, _) = root(&location.hive).create_subkey_transacted_with_flags(
            base(location),
            &tx,
            KEY_READ | KEY_WRITE | flags(location),
        )?;
        // create 返回的 disposition 和写入处于同一事务，不存在检查与写入间的覆盖竞态。
        let (key, disposition) = parent.create_subkey_transacted_with_flags(
            &location.key,
            &tx,
            KEY_READ | KEY_WRITE | flags(location),
        )?;
        ensure!(
            disposition == REG_CREATED_NEW_KEY,
            "{} 已存在；拒绝覆盖。整个恢复事务已取消",
            location.id()
        );
        write_tree(&key, &item.tree, flags(location), &tx)?;
        outcome.restored += 1;
    }
    tx.commit().context("恢复事务提交失败，已回滚")?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{self, BackupItem};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture(Location);
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(self.0.key.starts_with("CleanSoftware_Test_"));
            if let Ok(parent) = root(&self.0.hive)
                .open_subkey_with_flags(base(&self.0), KEY_READ | KEY_WRITE | flags(&self.0))
            {
                let _ = parent.delete_subkey_all(&self.0.key);
            }
        }
    }
    fn fixture(view: View) -> Result<(Fixture, RegKey)> {
        let id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let location = Location {
            hive: Hive::HKCU,
            view,
            key: format!("CleanSoftware_Test_{}_{id}", std::process::id()),
        };
        let (parent, _) = root(&location.hive)
            .create_subkey_with_flags(base(&location), KEY_READ | KEY_WRITE | flags(&location))?;
        let (key, disposition) = parent
            .create_subkey_with_flags(&location.key, KEY_READ | KEY_WRITE | flags(&location))?;
        ensure!(disposition == REG_CREATED_NEW_KEY, "测试键冲突");
        key.set_value("DisplayName", &"CleanSoftware integration 测试")?;
        // 根目录存在且路径带随机标识，确保不会碰真实应用。
        let drive = std::env::var("SystemDrive").unwrap_or("C:".into());
        let missing = format!("{drive}\\{}", location.key);
        key.set_value("InstallLocation", &missing)?;
        key.set_value(
            "UninstallString",
            &format!("\"{missing}\\uninstall.exe\" /S"),
        )?;
        Ok((Fixture(location), key))
    }

    #[test]
    fn native_registry_backup_delete_restore_both_views() -> Result<()> {
        let views = if os_is_64() {
            vec![View::Registry64, View::Registry32]
        } else {
            vec![View::Registry32]
        };
        for view in views {
            let (fixture, key) = fixture(view)?;
            key.set_raw_value(
                "binary",
                &RegValue {
                    vtype: REG_BINARY,
                    bytes: vec![0, 1, 255, 128],
                },
            )?;
            key.set_raw_value(
                "expand",
                &RegValue {
                    vtype: REG_EXPAND_SZ,
                    bytes: "%TEMP%"
                        .encode_utf16()
                        .chain(Some(0))
                        .flat_map(u16::to_le_bytes)
                        .collect(),
                },
            )?;
            let parent = open(
                &root(&Hive::HKCU),
                base(&fixture.0),
                flags(&fixture.0),
                None,
            )?;
            let entry = read_entry(&parent, fixture.0.clone(), None)?.unwrap();
            let assessed = detect::assess(entry, detect::probe);
            assert_eq!(assessed.status, Status::Candidate);
            let backup = Backup::from_assessments(&[&assessed]);
            let path = std::env::temp_dir().join(format!("{}.json", fixture.0.key));
            let result = (|| -> Result<()> {
                backup::save(&path, &backup)?;
                // 文件已存在时不能覆盖，也不能开始删除。
                assert!(backup::save(&path, &backup).is_err());
                drop(key);
                remove(&assessed, false)?;
                assert!(open(&parent, &fixture.0.key, flags(&fixture.0), None).is_err());
                restore(&backup::load(&path)?, false)?;
                let restored = read_entry(&parent, fixture.0.clone(), None)?.unwrap();
                assert_eq!(restored.tree, assessed.entry.tree);
                assert!(restore(&backup, false).is_err());
                assert_eq!(
                    read_entry(&parent, fixture.0.clone(), None)?.unwrap().tree,
                    restored.tree
                );
                Ok(())
            })();
            let _ = std::fs::remove_file(&path);
            result?;
        }
        Ok(())
    }

    #[test]
    fn manually_selected_review_entry_restores_nested_values() -> Result<()> {
        let view = if os_is_64() {
            View::Registry64
        } else {
            View::Registry32
        };
        let (fixture, key) = fixture(view)?;
        let (child, _) = key.create_subkey("metadata\\nested")?;
        child.set_value("中文", &vec!["一".to_string(), "二".to_string()])?;
        drop(child);
        drop(key);
        let parent = open(
            &root(&Hive::HKCU),
            base(&fixture.0),
            flags(&fixture.0),
            None,
        )?;
        let assessed = detect::assess(
            read_entry(&parent, fixture.0.clone(), None)?.unwrap(),
            detect::probe,
        );
        assert_eq!(assessed.status, Status::Review);
        assert!(remove(&assessed, false).is_err());
        let backup = Backup::from_assessments(&[&assessed]);
        remove(&assessed, true)?;
        restore(&backup, false)?;
        assert_eq!(
            read_entry(&parent, fixture.0.clone(), None)?.unwrap().tree,
            assessed.entry.tree
        );
        Ok(())
    }

    #[test]
    fn rejects_changed_and_protected_records_and_rolls_back_restore() -> Result<()> {
        let view = if os_is_64() {
            View::Registry64
        } else {
            View::Registry32
        };
        let (fixture, key) = fixture(view)?;
        let parent = open(
            &root(&Hive::HKCU),
            base(&fixture.0),
            flags(&fixture.0),
            None,
        )?;
        let assessed = detect::assess(
            read_entry(&parent, fixture.0.clone(), None)?.unwrap(),
            detect::probe,
        );
        key.set_value("NoRemove", &1u32)?;
        assert!(remove(&assessed, false).is_err());
        key.set_value("SystemComponent", &1u32)?;
        let protected = detect::assess(
            read_entry(&parent, fixture.0.clone(), None)?.unwrap(),
            detect::probe,
        );
        assert!(remove(&protected, true).is_err());
        let absent = Location {
            key: format!("{}_rollback", fixture.0.key),
            ..fixture.0.clone()
        };
        let rollback_guard = Fixture(absent.clone());
        let backup = Backup {
            format: "clean_software/v1".into(),
            created_unix_ms: 0,
            items: vec![
                BackupItem {
                    location: absent.clone(),
                    name: "new".into(),
                    tree: assessed.entry.tree.clone(),
                },
                BackupItem {
                    location: fixture.0.clone(),
                    name: "existing".into(),
                    tree: assessed.entry.tree,
                },
            ],
        };
        assert!(restore(&backup, false).is_err());
        assert!(open(&parent, &absent.key, flags(&absent), None).is_err());
        let outcome = restore(&backup, true)?;
        assert_eq!((outcome.restored, outcome.skipped), (1, 1));
        assert!(open(&parent, &absent.key, flags(&absent), None).is_ok());
        drop(rollback_guard);
        Ok(())
    }
}
