mod backup;
mod detect;
mod model;
#[cfg(windows)]
mod registry;

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use model::{Assessment, Status};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "清理 Windows 已安装应用中的卸载注册表残留（默认只扫描）"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 扫描疑似残留；不修改注册表
    Scan {
        #[command(flatten)]
        filter: Filter,
        /// 同时显示保留和受保护的正常记录
        #[arg(long)]
        all: bool,
        /// 输出 JSON（含证据、精确 ID 和扫描警告）
        #[arg(long)]
        json: bool,
    },
    /// 先备份，再删除符合条件的卸载记录；不删除软件文件
    Clean {
        #[command(flatten)]
        filter: Filter,
        /// 允许清理待核实记录，必须同时指定精确 --id
        #[arg(long, requires = "id")]
        include_review: bool,
        /// 只预览本次将删除的记录
        #[arg(long)]
        dry_run: bool,
        /// 跳过交互确认，适合一键运行
        #[arg(short = 'y', long)]
        yes: bool,
        /// 备份文件；默认保存至 LOCALAPPDATA\clean_software\backups
        #[arg(long)]
        backup: Option<PathBuf>,
    },
    /// 从本工具生成的 JSON 备份恢复；拒绝覆盖已存在的记录
    Restore {
        file: PathBuf,
        #[arg(short = 'y', long)]
        yes: bool,
        #[arg(long)]
        dry_run: bool,
        /// 跳过仍存在的记录（用于清理部分成功后的恢复），绝不覆盖
        #[arg(long)]
        skip_existing: bool,
    },
}

#[derive(Args, Default)]
struct Filter {
    /// 按应用名称过滤（不区分大小写的子串）
    #[arg(long)]
    name: Option<String>,
    /// 精确注册表 ID，可重复指定；从 scan 输出复制
    #[arg(long)]
    id: Vec<String>,
}

impl Filter {
    fn matches(&self, item: &Assessment) -> bool {
        self.name.as_ref().is_none_or(|name| {
            item.entry
                .name
                .to_lowercase()
                .contains(&name.to_lowercase())
        }) && (self.id.is_empty()
            || self
                .id
                .iter()
                .any(|id| id.eq_ignore_ascii_case(&item.entry.location.id())))
    }
}

fn confirm(yes: bool, count: usize, verb: &str) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    ensure!(io::stdin().is_terminal(), "非交互运行请使用 --yes 明确确认");
    print!("确认{verb} {count} 条卸载记录？输入 yes 继续: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}

fn show(items: &[&Assessment]) {
    for item in items {
        println!(
            "[{}] {} {}",
            item.status.label(),
            visible(&item.entry.name),
            visible(&item.entry.version)
        );
        println!("  ID: {}", visible(&item.entry.location.id()));
        for reason in &item.reasons {
            println!("  - {}", visible(reason));
        }
        for e in &item.evidence {
            println!(
                "  {}: {:?} ({})",
                e.field,
                visible(&e.source),
                e.state.label()
            );
        }
    }
}

// 注册表内容不能向终端注入 ANSI 控制序列或伪造新行。
fn visible(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(windows)]
fn run() -> Result<()> {
    let cli = Cli::parse();
    if let Some(Command::Restore {
        file,
        yes,
        dry_run,
        skip_existing,
    }) = cli.command
    {
        let backup = backup::load(&file)?;
        for item in &backup.items {
            println!(
                "恢复: {} ({})",
                visible(&item.name),
                visible(&item.location.id())
            );
        }
        if dry_run || !confirm(yes, backup.items.len(), "恢复")? {
            return Ok(());
        }
        let outcome = registry::restore(&backup, skip_existing)?;
        println!(
            "已恢复 {} 条，跳过 {} 条已存在记录。请重新打开 Windows 设置。",
            outcome.restored, outcome.skipped
        );
        return Ok(());
    }
    let report = registry::scan()?;
    let command = cli.command.unwrap_or(Command::Scan {
        filter: Filter::default(),
        all: false,
        json: false,
    });
    match command {
        Command::Scan { filter, all, json } => {
            let items: Vec<_> = report
                .items
                .iter()
                .filter(|item| filter.matches(item))
                .filter(|item| all || matches!(item.status, Status::Candidate | Status::Review))
                .collect();
            if json {
                serde_json::to_writer_pretty(
                    io::stdout().lock(),
                    &serde_json::json!({
                        "scanned": report.items.len(), "items": items, "warnings": report.warnings,
                    }),
                )?;
                println!();
            } else {
                show(&items);
                println!(
                    "扫描 {} 条，显示 {} 条；自动候选 {} 条。扫描未修改注册表。",
                    report.items.len(),
                    items.len(),
                    items
                        .iter()
                        .filter(|item| item.status == Status::Candidate)
                        .count()
                );
                for warning in report.warnings {
                    eprintln!("扫描警告: {}", visible(&warning));
                }
            }
        }
        Command::Clean {
            filter,
            include_review,
            dry_run,
            yes,
            backup: backup_path,
        } => {
            for warning in &report.warnings {
                eprintln!("扫描警告: {}", visible(warning));
            }
            let items = select(&report.items, &filter, include_review)?;
            show(&items);
            if items.is_empty() {
                println!("没有符合条件的卸载残留。");
                return Ok(());
            }
            if dry_run {
                println!("预览结束：将清理 {} 条，未修改注册表。", items.len());
                return Ok(());
            }
            if !confirm(yes, items.len(), "清理")? {
                println!("已取消。");
                return Ok(());
            }
            let path = backup_path.map(Ok).unwrap_or_else(backup::default_path)?;
            let backup = backup::Backup::from_assessments(&items);
            backup::save(&path, &backup)?;
            println!("备份已落盘: {}", path.display());
            let mut failed = 0;
            for item in items {
                match registry::remove(item, include_review) {
                    Ok(()) => println!("已清理: {}", visible(&item.entry.name)),
                    Err(error) => {
                        failed += 1;
                        eprintln!("跳过 {}: {error:#}", visible(&item.entry.name));
                    }
                }
            }
            ensure!(
                failed == 0,
                "{failed} 条记录未清理；权限不足的 HKLM 记录请在管理员终端重试。备份: {}",
                path.display()
            );
            println!("清理完成。请关闭并重新打开 Windows 的“安装的应用”。");
        }
        Command::Restore { .. } => unreachable!(),
    }
    Ok(())
}

fn select<'a>(
    items: &'a [Assessment],
    filter: &Filter,
    include_review: bool,
) -> Result<Vec<&'a Assessment>> {
    ensure!(
        !include_review || !filter.id.is_empty(),
        "--include-review 必须同时指定 --id"
    );
    let selected: Vec<_> = items
        .iter()
        .filter(|item| filter.matches(item))
        .filter(|item| {
            item.status == Status::Candidate || (include_review && item.status == Status::Review)
        })
        .collect();
    for id in &filter.id {
        ensure!(
            selected
                .iter()
                .any(|item| item.entry.location.id().eq_ignore_ascii_case(id)),
            "ID 不存在、不满足过滤条件或受到保护: {}。待核实记录需加 --include-review；保留/受保护记录不可清理。",
            visible(id)
        );
    }
    Ok(selected)
}

#[cfg(not(windows))]
fn run() -> Result<()> {
    Cli::parse();
    anyhow::bail!("此工具只支持 Windows")
}

fn main() {
    if let Err(error) = run().context("操作失败") {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_content_is_escaped() {
        assert_eq!(visible("a\x1b[31m\nb"), "a\\u{1b}[31m\\nb");
    }
    #[test]
    fn cli_requires_exact_ids_for_review() {
        assert!(
            Cli::try_parse_from(["clean_software", "clean", "--include-review", "-y"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "clean_software",
                "clean",
                "--id",
                "HKCU/64/test",
                "--include-review",
                "--dry-run"
            ])
            .is_ok()
        );
    }
}
