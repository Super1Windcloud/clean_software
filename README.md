# clean_software

Windows CLI：清理“设置 → 应用 → 安装的应用”中，软件已经移除但卸载注册表记录仍然存在的条目。Rust 实现，支持 Windows 10/11，构建需要 Rust 1.88+。

## 使用

在 PowerShell 中运行；系统级（HKLM）记录的清理/恢复通常需要管理员终端。

```powershell
cargo build --release --locked

# 默认只扫描，不改注册表
.\target\release\clean_software.exe

# 预览符合自动清理条件的记录
.\target\release\clean_software.exe clean --dry-run

# 一键清理候选记录，自动备份；去掉 --yes 则逐批确认
.\target\release\clean_software.exe clean --yes
```

只删除选中的 **Uninstall 卸载记录**。不会卸载软件、执行注册表里的命令、删除应用文件或扫描其他注册表位置。清理后关闭并重新打开 Windows 设置。

## 扫描和定向清理

```powershell
# 查看全部记录及判定证据，包括保留/受保护的记录
.\target\release\clean_software.exe scan --all

# 名称子串筛选，或者导出结构化数据（包含精确 id、路径证据和 warnings）
.\target\release\clean_software.exe scan --name '软件名称'
.\target\release\clean_software.exe scan --all --json

# ID 从 scan 输出原样复制，可重复指定 --id
.\target\release\clean_software.exe clean --id 'HKCU/64/注册表子键名' --dry-run

# 确认软件已经卸载后，定向清理“待核实”记录
.\target\release\clean_software.exe clean --id 'HKCU/64/注册表子键名' --include-review --yes
```

| 分类 | 规则 | 清理方式 |
| --- | --- | --- |
| 残留候选 | 安装目录和至少一个卸载程序/图标在在线本地固定磁盘上不存在，且其他已提供路径没有存在或未知证据 | `clean`，或 `clean --yes` |
| 待核实 | 证据不足、无法解析路径、禁止卸载标志、含安装器子键等 | 必须指定精确 `--id --include-review` |
| 保留 | 安装目录、卸载程序或图标任一仍存在 | 不允许清理 |
| 受保护 | MSI、系统组件、补丁、更新或子组件 | 不允许清理 |

**自动判定是启发式判断，无法证明软件真的卸载。** 推荐先看 `clean --dry-run`；迁移安装目录也可能留下失效条目。卸载按钮灰色可能是正常的 `NoRemove` 设置，不能直接视为残留。残留 MSI 请先使用厂商修复工具或 Windows Installer 处理。本工具不维护 MSI 产品数据库，不处理 Microsoft Store / Appx 的包注册。

路径含未解析环境变量、无引号且含空格的卸载命令、通用脚本启动器、UNC/网络盘、移动盘、离线盘、权限错误及经过 junction/symlink 的缺失路径，都不会提供自动清理所需的缺失证据。存在但空的安装目录也保留，避免误删仍在使用的记录。

## 备份与恢复

清理前完整保存选中记录的原始值类型、字节及子键到 JSON，并执行 `sync_all`。默认目录为 `%LOCALAPPDATA%\clean_software\backups`，每次使用新文件名，输出显示实际路径。可用 `--backup 'D:\Backups\apps.json'` 指定文件，已有文件绝不覆盖。备份包含选中的全部记录，包括后续因权限或变化而跳过的记录；不会保存注册表 ACL 和最后写入时间。

```powershell
.\target\release\clean_software.exe restore 'C:\路径\备份.json' --dry-run
.\target\release\clean_software.exe restore 'C:\路径\备份.json' --yes

# 清理只完成一部分时，跳过仍存在的记录、恢复缺失的记录，绝不覆盖
.\target\release\clean_software.exe restore 'C:\路径\备份.json' --skip-existing --yes
```

删除逐项使用 Windows 注册表事务，删除前再次检查原始数据和路径证据；条目变化则跳过。恢复整批使用同一事务，默认遇到已存在的记录即取消整批恢复；`--skip-existing` 显式跳过已存在的记录。事务不可用时直接失败，不降级为非事务写入。备份最大 32 MiB，只允许恢复到 HKCU/HKLM 的卸载子键，拒绝符号链接和异常子键路径。请在原机器、原用户下恢复。

## 覆盖范围与退出码

- HKLM：`Software\Microsoft\Windows\CurrentVersion\Uninstall` 的 64/32 位视图。
- HKCU：共享的 `Software\Microsoft\Windows\CurrentVersion\Uninstall`（64 位系统标为 `HKCU/64`）；另扫描部分安装器显式写入的 `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`（标为 `HKCU/32`），避免共享视图重复枚举。32 位系统只扫描原生位置。
- 仅当前用户，不加载其他用户的注册表配置单元。不使用会触发 MSI 修复的 `Win32_Product`。
- `0` 表示操作完成、没有候选或用户取消；`1` 表示错误/清理部分失败；`2` 表示命令参数错误。扫描权限错误进入警告列表，其他位置继续扫描；JSON 输出的 `warnings` 必须一并检查，存在警告时不能视为完整扫描。
- 非交互清理或恢复必须指定 `--yes`。权限不足时给出错误，不会自动提权。

## 验证

```powershell
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

测试在 HKCU 中创建带随机标识的 `CleanSoftware_Test_*` / `CleanSoftware_CliTest_*` 临时卸载记录，仅删除这些测试记录，并清理系统临时目录中的测试备份；不清理真实应用记录。覆盖 32/64 位位置、原始类型和多层子键往返、扫描后记录变化、受保护条目拒绝、恢复冲突回滚及 CLI 的预览/确认/备份失败路径。

参考：[卸载注册表字段](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key)、[NoRemove](https://learn.microsoft.com/en-us/windows/win32/msi/arpnoremove)、[注册表视图](https://learn.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry)。
