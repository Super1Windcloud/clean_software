#![cfg(windows)]

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use winreg::{RegKey, enums::*};

const BASE: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

struct Fixture {
    key: String,
    directory: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.key.starts_with("CleanSoftware_CliTest_"));
        if let Ok(parent) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(BASE, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY)
        {
            let _ = parent.delete_subkey_all(&self.key);
        }
        // 仅清理本测试明确创建的文件，无递归目录删除。
        let _ = std::fs::remove_file(self.directory.join("backup.json"));
        let _ = std::fs::remove_file(self.directory.join("blocked.json"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn run(args: &[&str]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_clean_software"))
        .args(args)
        .stdin(Stdio::null())
        .output()?)
}
fn success(output: Output) -> Result<Output> {
    ensure!(
        output.status.success(),
        "CLI 失败: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

#[test]
fn cli_previews_backs_up_cleans_and_restores_only_exact_fixture() -> Result<()> {
    let unique = format!(
        "CleanSoftware_CliTest_{}_{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let fixture = Fixture {
        directory: std::env::temp_dir().join(&unique),
        key: unique,
    };
    std::fs::create_dir(&fixture.directory)?;
    let parent = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(BASE, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY)?;
    let (key, disposition) = parent.create_subkey(&fixture.key)?;
    ensure!(disposition == REG_CREATED_NEW_KEY, "测试键冲突");
    key.set_value("DisplayName", &fixture.key)?;
    let missing = format!("{}\\{}", std::env::var("SystemDrive")?, fixture.key);
    key.set_value("InstallLocation", &missing)?;
    key.set_value(
        "UninstallString",
        &format!("\"{missing}\\uninstall.exe\" /S"),
    )?;
    drop(key);

    let output = success(run(&["scan", "--name", &fixture.key, "--json"])?)?;
    let json: Value = serde_json::from_slice(&output.stdout)?;
    let items = json["items"].as_array().context("JSON items")?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["status"], "candidate");
    let id = items[0]["id"].as_str().context("JSON ID")?;
    let path = fixture.directory.join("backup.json");
    let path_str = path.to_str().context("备份路径")?;
    success(run(&[
        "clean",
        "--id",
        id,
        "--dry-run",
        "--backup",
        path_str,
    ])?)?;
    assert!(!path.exists());
    assert!(parent.open_subkey(&fixture.key).is_ok());

    // 非交互运行没有 --yes 时必须拒绝，也不产生备份。
    assert!(
        !run(&["clean", "--id", id, "--backup", path_str])?
            .status
            .success()
    );
    assert!(!path.exists());
    let blocked = fixture.directory.join("blocked.json");
    std::fs::write(&blocked, "do not overwrite")?;
    assert!(
        !run(&[
            "clean",
            "--id",
            id,
            "--yes",
            "--backup",
            blocked.to_str().unwrap()
        ])?
        .status
        .success()
    );
    assert_eq!(std::fs::read_to_string(&blocked)?, "do not overwrite");
    assert!(parent.open_subkey(&fixture.key).is_ok());

    success(run(&["clean", "--id", id, "--yes", "--backup", path_str])?)?;
    assert!(path.exists());
    assert!(parent.open_subkey(&fixture.key).is_err());
    let saved: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(saved["items"].as_array().unwrap().len(), 1);
    assert_eq!(saved["items"][0]["location"]["key"], fixture.key);
    success(run(&["restore", path_str, "--dry-run"])?)?;
    assert!(parent.open_subkey(&fixture.key).is_err());
    success(run(&["restore", path_str, "--yes"])?)?;
    assert_eq!(
        parent
            .open_subkey(&fixture.key)?
            .get_value::<String, _>("InstallLocation")?,
        missing
    );
    assert!(!run(&["restore", path_str, "--yes"])?.status.success());
    success(run(&["restore", path_str, "--yes", "--skip-existing"])?)?;
    assert!(
        !run(&["clean", "--id", "HKCU/64/does-not-exist", "--yes"])?
            .status
            .success()
    );
    Ok(())
}
