use crate::model::{Assessment, Location, Tree, validate_key_name};

const MAX_BACKUP_BYTES: u64 = 32 * 1024 * 1024;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub format: String,
    pub created_unix_ms: u128,
    pub items: Vec<BackupItem>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupItem {
    pub location: Location,
    pub name: String,
    pub tree: Tree,
}

impl Backup {
    pub fn from_assessments(items: &[&Assessment]) -> Self {
        Self {
            format: "clean_software/v1".into(),
            created_unix_ms: now_ms(),
            items: items
                .iter()
                .map(|a| BackupItem {
                    location: a.entry.location.clone(),
                    name: a.entry.name.clone(),
                    tree: a.entry.tree.clone(),
                })
                .collect(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.format == "clean_software/v1", "不支持的备份格式");
        ensure!(!self.items.is_empty(), "备份没有记录");
        let mut ids = HashSet::new();
        for item in &self.items {
            item.location.validate()?;
            ensure!(
                ids.insert(item.location.id().to_ascii_lowercase()),
                "备份含重复 ID"
            );
            validate_tree(&item.tree, 0)?;
        }
        Ok(())
    }
}

fn validate_tree(tree: &Tree, depth: usize) -> Result<()> {
    ensure!(depth <= 32, "注册表子树深度超过限制");
    let mut names = HashSet::new();
    for (name, value) in &tree.values {
        ensure!(
            !name.contains(['\0', '\u{fffd}']) && names.insert(name.to_lowercase()),
            "备份含非法/重复值名"
        );
        ensure!(
            value.kind <= 11 && value.kind != 6,
            "不支持的注册表类型或符号链接"
        );
        ensure!(
            !name.eq_ignore_ascii_case("SymbolicLinkValue"),
            "拒绝注册表符号链接"
        );
    }
    let mut children = HashSet::new();
    for (name, child) in &tree.children {
        validate_key_name(name)?;
        ensure!(children.insert(name.to_lowercase()), "备份含重复子键");
        validate_tree(child, depth + 1)?;
    }
    Ok(())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn default_path() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .context("LOCALAPPDATA 不存在，请使用 --backup 指定文件")?;
    Ok(PathBuf::from(base)
        .join("clean_software")
        .join("backups")
        .join(format!("{}-{}.json", now_ms(), std::process::id())))
}

pub fn save(path: &Path, backup: &Backup) -> Result<()> {
    backup.validate()?;
    let bytes = serde_json::to_vec_pretty(backup)?;
    ensure!(
        (bytes.len() as u64) < MAX_BACKUP_BYTES,
        "备份超过 32 MiB 限制，未开始清理"
    );
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    // create_new 保证绝不覆盖历史备份；落盘成功后才允许改动注册表。
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("无法创建备份 {}（已有文件不会覆盖）", path.display()))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all().context("备份落盘失败，已中止清理")?;
    Ok(())
}

pub fn load(path: &Path) -> Result<Backup> {
    let file = File::open(path).with_context(|| format!("无法读取备份 {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= MAX_BACKUP_BYTES,
        "备份超过 32 MiB 限制"
    );
    let backup: Backup = serde_json::from_reader(BufReader::new(file)).context("备份 JSON 无效")?;
    backup.validate()?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Hive, RawValue, View};
    #[test]
    fn backup_is_lossless_and_refuses_overwrite() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "clean-software-unit-{}-{}.json",
            std::process::id(),
            now_ms()
        ));
        let mut tree = Tree::default();
        tree.values.insert(
            "".into(),
            RawValue {
                kind: 3,
                bytes: vec![0, 255, 128],
            },
        );
        tree.children.insert("child".into(), Tree::default());
        let backup = Backup {
            format: "clean_software/v1".into(),
            created_unix_ms: now_ms(),
            items: vec![BackupItem {
                location: Location {
                    hive: Hive::HKCU,
                    view: View::Registry64,
                    key: "test".into(),
                },
                name: "中文".into(),
                tree,
            }],
        };
        let result = (|| -> Result<()> {
            save(&path, &backup)?;
            assert!(save(&path, &backup).is_err());
            assert_eq!(load(&path)?.items[0].tree, backup.items[0].tree);
            Ok(())
        })();
        let _ = fs::remove_file(&path);
        result
    }
    #[test]
    fn rejects_path_escape_and_registry_links() {
        let mut backup = Backup {
            format: "clean_software/v1".into(),
            created_unix_ms: 0,
            items: vec![BackupItem {
                location: Location {
                    hive: Hive::HKCU,
                    view: View::Registry64,
                    key: r"test\child".into(),
                },
                name: "test".into(),
                tree: Tree::default(),
            }],
        };
        assert!(backup.validate().is_err());
        backup.items[0].location.key = "valid".into();
        backup.items[0].tree.values.insert(
            "link".into(),
            RawValue {
                kind: 6,
                bytes: vec![],
            },
        );
        assert!(backup.validate().is_err());
    }
}
